"""Alert lifecycle, deduplication and storm protection (PS capability 08).

An alert is not a message, it is an object with a life:

    raised -> delivered -> acknowledged -> adjudicated -> closed

Suppression is what separates a usable system from one that gets switched
off in week two. Four mechanisms, in order of how much they matter:

  per-track dedup       one person crossing one line is ONE alert, not one
                        per frame. The track id is the dedup key.
  cooldown windows      the same rule, zone and class inside N seconds
                        folds into the existing alert as an occurrence.
  cross-camera join     the same intruder seen by three cameras is one
                        incident with three views. (Joined on track+time
                        here; on the ReID embedding in Phase 3.)
  storm protection      a spider on the lens, a herd, or a thunderstorm
                        raises ONE "anomalous alert rate" meta-alert
                        instead of five hundred rows.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional

from ..perception.rules import RuleEvent, Severity
from .alarm import AlarmDispatcher
from .autonomy import AutonomyEngine, Band
from .store import Store, sha256_file

log = logging.getLogger("prahari.server.alerts")

MODEL_VERSION = "prahari-p0-motion-0.1"


class State:
    RAISED = "raised"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    ADJUDICATED = "adjudicated"
    CLOSED = "closed"


@dataclass
class Incident:
    """A cross-camera grouping of alerts that are the same real event."""
    incident_id: str
    started: float
    last: float
    cameras: List[str] = field(default_factory=list)
    alert_uids: List[str] = field(default_factory=list)


class AlertManager:
    def __init__(self, store: Store,
                 publish: Optional[Callable[[str, dict], None]] = None,
                 cooldown_s: float = 25.0,
                 storm_threshold: int = 12,
                 storm_window_s: float = 60.0,
                 storm_mute_s: float = 120.0,
                 incident_window_s: float = 30.0,
                 model_version: str = MODEL_VERSION,
                 autonomy: Optional[AutonomyEngine] = None,
                 alarms: Optional[AlarmDispatcher] = None):
        self.store = store
        self.publish = publish
        self.cooldown_s = cooldown_s
        self.storm_threshold = storm_threshold
        self.storm_window_s = storm_window_s
        self.storm_mute_s = storm_mute_s
        self.incident_window_s = incident_window_s
        self.model_version = model_version
        # Deciding for itself what deserves a person. Without this the
        # system is a firehose that needs somebody sitting in front of it.
        self.autonomy = autonomy or AutonomyEngine()
        self.alarms = alarms
        self._lock = threading.Lock()
        self._recent: Dict[str, tuple] = {}          # dedup key -> (uid, ts)
        self._rate: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=400))
        self._muted_until: Dict[str, float] = {}
        self._incidents: List[Incident] = []
        self.counters = defaultdict(int)

    # ------------------------------------------------------------------
    @staticmethod
    def dedup_key(ev: RuleEvent) -> str:
        """One person, one line, one crossing -- keyed on the track."""
        return "|".join([ev.camera_id, ev.rule_id, ev.rule_type,
                         ev.label, str(ev.track_id)])

    @staticmethod
    def _uid(ev: RuleEvent) -> str:
        raw = f"{ev.camera_id}|{ev.rule_id}|{ev.track_id}|{ev.ts:.3f}|{uuid.uuid4()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    # ------------------------------------------------------------------
    def _storm_check(self, camera_id: str, ts: float) -> bool:
        """True when this camera is storming and should be muted."""
        window = self._rate[camera_id]
        window.append(ts)
        while window and ts - window[0] > self.storm_window_s:
            window.popleft()
        return len(window) >= self.storm_threshold

    def _raise_storm(self, camera_id: str, ts: float, count: int) -> None:
        uid = hashlib.sha256(f"storm|{camera_id}|{int(ts)}".encode()).hexdigest()[:20]
        row = {
            "alert_uid": uid, "ts": ts, "camera_id": camera_id,
            "camera_name": camera_id, "rule_id": "storm",
            "rule_type": "alert_storm", "label": "camera",
            "track_id": -1, "severity": Severity.HIGH.value,
            "state": State.RAISED,
            "message": (f"anomalous alert rate on {camera_id}: {count} in "
                        f"{int(self.storm_window_s)}s -- muting for "
                        f"{int(self.storm_mute_s)}s and flagging for review"),
            "attributes": json.dumps({"count": count, "auto": True}),
            "model_version": self.model_version, "last_ts": ts,
        }
        self.store.insert_alert(row)
        self.store.audit("system", "alert.storm", camera_id,
                         {"count": count})
        self.counters["storms"] += 1
        if self.publish:
            self.publish("alert", self.store.alert(uid) or row)

    # ------------------------------------------------------------------
    def _incident_for(self, ev: RuleEvent, uid: str) -> str:
        """Join alerts close in time into one incident across cameras."""
        now = ev.ts
        self._incidents = [i for i in self._incidents
                           if now - i.last <= self.incident_window_s]
        for inc in self._incidents:
            if now - inc.last <= self.incident_window_s:
                inc.last = now
                inc.alert_uids.append(uid)
                if ev.camera_id not in inc.cameras:
                    inc.cameras.append(ev.camera_id)
                return inc.incident_id
        inc = Incident(incident_id=uuid.uuid4().hex[:12], started=now,
                       last=now, cameras=[ev.camera_id], alert_uids=[uid])
        self._incidents.append(inc)
        return inc.incident_id

    # ------------------------------------------------------------------
    def handle(self, ev: RuleEvent, meta: Optional[dict] = None) -> Optional[dict]:
        """Entry point from a camera worker. Returns the stored alert, or
        None when the event was folded into an existing one."""
        meta = meta or {}
        with self._lock:
            self.counters["events_in"] += 1
            key = self.dedup_key(ev)
            prior = self._recent.get(key)
            if prior and (ev.ts - prior[1]) < self.cooldown_s:
                self.store.bump_alert(prior[0], ev.ts)
                self.counters["deduped"] += 1
                if self.publish:
                    self.publish("alert_update",
                                 {"alert_uid": prior[0], "ts": ev.ts})
                return None

            muted_until = self._muted_until.get(ev.camera_id, 0.0)
            if ev.ts < muted_until:
                self.counters["muted"] += 1
                return None

            if ev.rule_type != "alert_storm" and self._storm_check(
                    ev.camera_id, ev.ts):
                self._muted_until[ev.camera_id] = ev.ts + self.storm_mute_s
                self._raise_storm(ev.camera_id, ev.ts,
                                  len(self._rate[ev.camera_id]))
                return None

            uid = self._uid(ev)
            self._recent[key] = (uid, ev.ts)
            incident = self._incident_for(ev, uid)

            clip = meta.get("evidence_clip") or ""
            attrs = dict(ev.attributes)
            attrs["incident_id"] = incident
            if meta.get("optics"):
                attrs["optics"] = meta["optics"]
            if meta.get("role"):
                attrs["camera_role"] = meta["role"]

            caps = meta.get("capabilities") or {}
            # If this view cannot physically support the claim (plates at
            # 40 px, faces at 4 px), a confident model is not enough.
            capability_ok = True
            if ev.rule_type in ("anpr",) and caps:
                capability_ok = bool(caps.get("anpr", True))
            if ev.rule_type in ("face_match",) and caps:
                capability_ok = bool(caps.get("face_match", True))

            probe = {
                "ts": ev.ts, "camera_id": ev.camera_id,
                "track_id": ev.track_id, "rule_id": ev.rule_id,
                "rule_type": ev.rule_type, "severity": ev.severity.value,
                "attributes": {**dict(ev.attributes),
                               "zone_criticality": meta.get(
                                   "zone_criticality", "normal")},
            }
            decision = self.autonomy.decide(
                probe,
                anomaly=meta.get("anomaly"),
                track_quality=meta.get("track_quality"),
                capability_ok=capability_ok)

            row = {
                "alert_uid": uid,
                "ts": ev.ts,
                "camera_id": ev.camera_id,
                "camera_name": meta.get("camera_name", ev.camera_id),
                "bop": meta.get("bop", ""),
                "rule_id": ev.rule_id,
                "rule_type": ev.rule_type,
                "label": ev.label,
                "track_id": ev.track_id,
                "severity": ev.severity.value,
                "state": State.RAISED,
                "message": ev.message,
                "direction": ev.direction,
                "dwell_s": ev.dwell_s,
                "speed_kmh": ev.speed_kmh,
                "ground_x": ev.ground_m[0] if ev.ground_m else None,
                "ground_y": ev.ground_m[1] if ev.ground_m else None,
                "box": json.dumps([round(v, 1) for v in ev.box]),
                "attributes": json.dumps(attrs, default=str),
                "evidence_clip": clip,
                "thumbnail": meta.get("thumbnail", ""),
                "evidence_sha": sha256_file(clip) if clip else "",
                "model_version": self.model_version,
                "detector": meta.get("detector", ""),
                "occurrences": 1,
                "last_ts": ev.ts,
                "band": decision.band.value,
                "decision_score": decision.score,
                "anomaly_score": float((meta.get("anomaly") or {}).get(
                    "score", 0.0)),
                "decision": json.dumps(decision.as_dict(), default=str),
            }
            self.store.insert_alert(row)
            self.counters["raised"] += 1
            self.counters[f"band_{decision.band.value}"] += 1

        stored = self.store.alert(uid) or row
        self.store.audit("system", "alert.raised", uid,
                         {"camera": ev.camera_id, "rule": ev.rule_id,
                          "severity": ev.severity.value,
                          "band": decision.band.value,
                          "score": round(decision.score, 3)})

        # AUTO_LOG is stored, hashed and searchable -- it is simply not
        # pushed at anybody. That is the whole point: the archive stays
        # complete while the operator's queue stays short.
        if decision.band is not Band.AUTO_LOG:
            if self.publish:
                self.publish("alert", stored)
            self.store.update_alert(uid, state=State.DELIVERED)

        if decision.band is Band.AUTO_ALARM and self.alarms:
            fired = self.alarms.fire(stored, decision.as_dict())
            self.store.audit("system", "alarm.fired", uid,
                             {"sinks": fired,
                              "reasons": decision.reasons,
                              "overrides": decision.overrides})
            self.counters["alarms"] += 1
        return stored

    # ------------------------------------------------------------------
    # operator actions
    # ------------------------------------------------------------------
    def acknowledge(self, alert_uid: str, actor: str) -> Optional[dict]:
        if self.alarms:
            self.alarms.acknowledge(alert_uid)
        self.store.update_alert(alert_uid, state=State.ACKNOWLEDGED,
                                acknowledged_by=actor,
                                acknowledged_ts=time.time())
        self.store.audit(actor, "alert.acknowledged", alert_uid)
        alert = self.store.alert(alert_uid)
        if self.publish and alert:
            self.publish("alert_update", alert)
        return alert

    def adjudicate(self, alert_uid: str, verdict: str, actor: str,
                   note: str = "") -> Optional[dict]:
        """Confirm or dismiss.

        A dismissal is not just a state change: it queues the frame for
        labelling, which is the active-learning loop. The operator is
        labelling training data without knowing it.
        """
        verdict = "true" if verdict.lower() in ("true", "confirm",
                                                "confirmed") else "false"
        self.store.update_alert(alert_uid, state=State.ADJUDICATED,
                                adjudication=verdict, closed_ts=time.time())
        self.store.add_label(alert_uid, verdict, actor, note)
        self.store.audit(actor, "alert.adjudicated", alert_uid,
                         {"verdict": verdict, "note": note})
        self.counters[f"adjudicated_{verdict}"] += 1
        alert = self.store.alert(alert_uid)
        if self.publish and alert:
            self.publish("alert_update", alert)
        return alert

    # ------------------------------------------------------------------
    def metrics(self) -> dict:
        raised = self.counters["raised"] or 0
        events = self.counters["events_in"] or 0
        # Always report the full counter set. These come from a defaultdict,
        # so an untouched counter would otherwise be absent rather than zero,
        # and a dashboard reading it back gets null instead of 0.
        base = {"events_in": 0, "raised": 0, "deduped": 0, "muted": 0,
                "storms": 0, "adjudicated_true": 0, "adjudicated_false": 0}
        return {
            **base,
            **{k: v for k, v in self.counters.items()},
            "dedup_ratio": round(1 - (raised / events), 3) if events else 0.0,
            "muted_cameras": [c for c, until in self._muted_until.items()
                              if until > time.time()],
            "open_incidents": len(self._incidents),
            "autonomy": self.autonomy.metrics(),
            "alarms": self.alarms.status() if self.alarms else None,
        }
