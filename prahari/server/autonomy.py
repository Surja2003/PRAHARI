"""Deciding, without a human, what deserves a siren.

The operational objection to every video-analytics system is the same one:
"who sits and reads all these alerts?" At a border outpost at 03:00 the
honest answer is nobody. So the system has to make the call itself, and it
has to be wrong in the safe direction.

Three bands, not two:

  AUTO_ALARM   act now. Siren, radio, priority to the control room. No
               human was required to reach this decision.
  REVIEW       a person should look when a person is next available. Does
               not sound anything, does not block.
  AUTO_LOG     recorded, hashed, searchable, and shown to nobody.

What separates them is not one model's confidence. A single detector being
confident is exactly how false alarms happen. What separates them is
CORROBORATION -- several signals that fail independently agreeing at once:

  the rule that fired, and how critical its zone is
  how solid the track was (hits, duration, class stability)
  how surprising it is for THIS camera at THIS hour (learned baseline)
  whether another camera saw the same incident
  whether more than one rule fired on the same track
  whether the view can even support the claim being made

Corroboration is what a good operator uses, and it is what replaces them.

Fail-safe, never fail-quiet. Tamper, critical zones and cross-camera
corroboration are floors that cannot be scored away: the worst outcome for
this system is not a needless siren, it is a silent one.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional

from ..perception.rules import Severity


class Band(str, Enum):
    AUTO_ALARM = "auto_alarm"
    REVIEW = "review"
    AUTO_LOG = "auto_log"


SEVERITY_WEIGHT = {
    Severity.INFO.value: 0.05,
    Severity.LOW.value: 0.20,
    Severity.MEDIUM.value: 0.45,
    Severity.HIGH.value: 0.72,
    Severity.CRITICAL.value: 0.95,
}

#: Rules that describe an attack on the system itself, or an event whose
#: cost of being missed is unbounded. These never get auto-logged.
NEVER_SILENT = {"tamper", "alert_storm"}


@dataclass
class Signal:
    name: str
    value: float          # 0..1
    weight: float
    detail: str = ""

    @property
    def contribution(self) -> float:
        return self.value * self.weight


@dataclass
class Decision:
    band: Band
    score: float
    signals: List[Signal] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    overrides: List[str] = field(default_factory=list)
    needs_human: bool = False
    alarm: bool = False

    def as_dict(self) -> dict:
        return {
            "band": self.band.value,
            "score": round(self.score, 3),
            "needs_human": self.needs_human,
            "alarm": self.alarm,
            "reasons": self.reasons,
            "overrides": self.overrides,
            "signals": [{"name": s.name, "value": round(s.value, 3),
                         "weight": s.weight, "detail": s.detail}
                        for s in self.signals],
        }


@dataclass
class AutonomyPolicy:
    """Thresholds an operator can defend in a review, not magic numbers."""
    alarm_threshold: float = 0.62
    review_threshold: float = 0.30
    #: Below this the baseline has not seen enough to be allowed to dismiss
    #: anything; the system stays supervised until it has.
    require_mature_to_dismiss: bool = True
    #: Never auto-log anything in these zones, whatever it scores.
    critical_zones: tuple = ("critical",)
    #: A quiet-hours multiplier: the same event at 03:00 matters more.
    night_boost: float = 1.15

    @classmethod
    def from_env(cls) -> "AutonomyPolicy":
        return cls(
            alarm_threshold=float(os.environ.get(
                "PRAHARI_ALARM_THRESHOLD", "0.62")),
            review_threshold=float(os.environ.get(
                "PRAHARI_REVIEW_THRESHOLD", "0.30")),
        )


class AutonomyEngine:
    """Scores every candidate alert and decides who, if anyone, is told."""

    def __init__(self, policy: Optional[AutonomyPolicy] = None,
                 corroboration_window_s: float = 45.0):
        self.policy = policy or AutonomyPolicy.from_env()
        self.window = corroboration_window_s
        self._recent: Deque[dict] = deque(maxlen=400)
        self._lock = threading.Lock()
        self.counts: Dict[str, int] = defaultdict(int)
        self._started = time.time()
        self._human_events: Deque[float] = deque(maxlen=5000)

    # ------------------------------------------------------------------
    def _corroboration(self, alert: dict) -> tuple:
        """Did anything else independently see something UNUSUAL?

        Counting concurrent events is not enough. Nine cameras all
        reporting a routine crossing at 09:00 is a shift change, not an
        incident, and treating simple coincidence as evidence turns every
        patrol into an alarm. So each corroborating event is weighted by
        how anomalous IT was: agreement between things that are each
        surprising is strong evidence; agreement between things that are
        each ordinary is a timetable.
        """
        now = float(alert.get("ts") or time.time())
        cam = alert.get("camera_id")
        track = alert.get("track_id")
        other_cams: Dict[str, float] = {}
        same_track_rules: Dict[str, float] = {}
        with self._lock:
            for prior in self._recent:
                # abs(): events replayed out of order after a store-and-
                # forward flush have a negative delta, which sails past a
                # signed comparison and counts as corroboration for
                # something that happened days apart.
                if abs(now - prior["ts"]) > self.window:
                    continue
                weight = max(0.15, float(prior.get("anomaly", 0.0)))
                if prior["camera"] != cam:
                    other_cams[prior["camera"]] = max(
                        other_cams.get(prior["camera"], 0.0), weight)
                elif (prior["track"] == track
                      and prior["rule"] != alert.get("rule_id")):
                    same_track_rules[prior["rule"]] = max(
                        same_track_rules.get(prior["rule"], 0.0), weight)
        return other_cams, same_track_rules

    def _remember(self, alert: dict, anomaly_score: float = 0.0):
        with self._lock:
            self._recent.append({
                "ts": float(alert.get("ts") or time.time()),
                "camera": alert.get("camera_id"),
                "track": alert.get("track_id"),
                "rule": alert.get("rule_id"),
                "anomaly": anomaly_score,
            })

    # ------------------------------------------------------------------
    def decide(self, alert: dict, anomaly: Optional[dict] = None,
               track_quality: Optional[dict] = None,
               capability_ok: bool = True) -> Decision:
        anomaly = anomaly or {}
        track_quality = track_quality or {}
        signals: List[Signal] = []
        reasons: List[str] = []
        overrides: List[str] = []

        sev = str(alert.get("severity", "low"))
        rule_type = str(alert.get("rule_type", ""))
        attrs = alert.get("attributes") or {}
        if isinstance(attrs, str):
            attrs = {}
        night = bool(attrs.get("night"))
        criticality = str(attrs.get("zone_criticality", "normal"))

        # 1. what the rule itself claims -------------------------------
        signals.append(Signal("rule_severity", SEVERITY_WEIGHT.get(sev, 0.2),
                              0.30, f"{rule_type} @ {sev}"))

        # 2. how solid was the observation ------------------------------
        # Solidity GATES, it does not add. A confidently observed routine
        # crossing is still routine, and if solidity were another additive
        # term every clean daytime track would drift into the review queue
        # -- which is precisely the flood this layer exists to stop. A
        # flimsy track discounts the score; a solid one simply does not
        # discount it.
        hits = float(track_quality.get("hits", 0))
        conf = float(track_quality.get("score", 0.0))
        stability = float(track_quality.get("class_stability", 1.0))
        solidity = min(1.0, hits / 20.0) * 0.5 + conf * 0.25 + stability * 0.25
        gate = 0.55 + 0.45 * min(1.0, solidity)

        # 3. is this unusual for this camera at this hour ----------------
        a_score = float(anomaly.get("score", 0.0))
        a_mature = bool(anomaly.get("mature"))
        signals.append(Signal(
            "learned_anomaly", a_score if a_mature else 0.0, 0.45,
            "baseline still learning" if not a_mature
            else "; ".join(anomaly.get("reasons") or []) or "within normal range"))
        if a_mature and a_score > 0.5:
            reasons.extend(anomaly.get("reasons") or [])

        # 4. did anything else see it ------------------------------------
        other_cams, same_track_rules = self._corroboration(alert)
        corr = min(1.0, 0.6 * sum(other_cams.values())
                   + 0.4 * sum(same_track_rules.values()))
        detail = []
        if other_cams:
            detail.append(f"{len(other_cams)} other camera(s)")
        if same_track_rules:
            detail.append(f"{len(same_track_rules)} other rule(s)")
        signals.append(Signal("corroboration", corr, 0.25,
                              ", ".join(detail) or "single source"))
        if corr > 0:
            reasons.append("corroborated by " + " and ".join(detail))

        score = sum(s.contribution for s in signals) / sum(
            s.weight for s in signals)
        score *= gate

        # Familiarity damper. An additive anomaly term can only ever push a
        # score UP, so a camera that has watched the same gate for a
        # fortnight and is certain this crossing is routine still could not
        # stop it reaching an operator -- severity and corroboration alone
        # carried it. That is the flood the whole layer exists to prevent.
        #
        # So once a baseline is mature it is allowed to argue the other
        # way: strong familiarity discounts the score. It only ever damps
        # within the routine range, never below half, and never at all once
        # the event is even mildly unusual -- and it cannot touch the
        # fail-safe floors below.
        if a_mature and a_score < 0.35:
            damp = 0.5 + 0.5 * (a_score / 0.35)
            score *= damp
            if damp < 0.8:
                reasons.append(
                    f"this camera has seen this pattern many times "
                    f"({anomaly.get('observations', 0)} tracks learned)")
        signals.append(Signal("track_solidity", min(1.0, solidity), 0.0,
                              f"{int(hits)} frames, conf {conf:.2f} "
                              f"(gate x{gate:.2f})"))

        if night:
            score = min(1.0, score * self.policy.night_boost)
            reasons.append("after dark")

        # --- fail-safe floors -----------------------------------------
        band = (Band.AUTO_ALARM if score >= self.policy.alarm_threshold
                else Band.REVIEW if score >= self.policy.review_threshold
                else Band.AUTO_LOG)

        if rule_type in NEVER_SILENT:
            band = Band.AUTO_ALARM
            overrides.append(f"{rule_type} is never silenced")
        if criticality in self.policy.critical_zones:
            if band is Band.AUTO_LOG:
                band = Band.REVIEW
            overrides.append("critical zone: never auto-logged")
        # Promote on corroboration only when at least one corroborating
        # sighting was ITSELF unusual. Several cameras agreeing that
        # something ordinary happened is a patrol timetable; promoting on
        # bare simultaneity re-creates the flood this layer removes.
        strongest = max(other_cams.values(), default=0.0)
        if strongest >= 0.4 and band is Band.AUTO_LOG:
            band = Band.REVIEW
            overrides.append(
                f"another camera saw something unusual at the same moment "
                f"(anomaly {strongest:.2f})")
        if (self.policy.require_mature_to_dismiss and not a_mature
                and band is Band.AUTO_LOG):
            band = Band.REVIEW
            overrides.append(
                "baseline immature: nothing is dismissed until this camera "
                "has learned what normal looks like")
        if not capability_ok and band is Band.AUTO_ALARM:
            band = Band.REVIEW
            overrides.append(
                "this view cannot physically support the claim; "
                "downgraded for human confirmation")

        decision = Decision(
            band=band, score=score, signals=signals, reasons=reasons,
            overrides=overrides,
            needs_human=band is Band.REVIEW,
            alarm=band is Band.AUTO_ALARM)

        self._remember(alert, a_score if a_mature else 0.0)
        self.counts[band.value] += 1
        self.counts["total"] += 1
        if band in (Band.AUTO_ALARM, Band.REVIEW):
            self._human_events.append(time.time())
        return decision

    # ------------------------------------------------------------------
    def metrics(self) -> dict:
        hours = max((time.time() - self._started) / 3600.0, 1e-6)
        total = self.counts.get("total", 0)
        surfaced = (self.counts.get(Band.AUTO_ALARM.value, 0)
                    + self.counts.get(Band.REVIEW.value, 0))
        return {
            "total": total,
            "auto_alarm": self.counts.get(Band.AUTO_ALARM.value, 0),
            "review": self.counts.get(Band.REVIEW.value, 0),
            "auto_log": self.counts.get(Band.AUTO_LOG.value, 0),
            # The number that answers "who sits and reads all these?"
            "operator_load_per_hour": round(
                self.counts.get(Band.REVIEW.value, 0) / hours, 2),
            "autonomy_ratio": round(
                1 - (surfaced / total), 3) if total else 0.0,
            "alarm_threshold": self.policy.alarm_threshold,
            "review_threshold": self.policy.review_threshold,
        }
