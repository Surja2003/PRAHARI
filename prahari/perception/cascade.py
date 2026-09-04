"""The false-alarm cascade -- the part that decides whether SSB keeps the
system switched on.

Operators abandon any system that cries wolf, so the headline metric here
is not mAP, it is false alarms per camera per hour. Five stages, cheap
first, each killing a class of false positive before the expensive stage
runs. Stages 1 and 2 live in the detector (motion gate, then the network);
this module is stages 3 to 5, which act on candidate rule events.

  3  temporal confirmation   flicker, insects on the IR lens, rain streaks
  4  class verification      cattle and stray dogs -- the number one false
                             alarm on the Indo-Nepal border
  5  contextual policy       legitimate daytime movement in a corridor
                             where a treaty permits free movement
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from .detect import ANIMAL, PERSON
from .rules import RuleEvent, Severity, escalate
from .track import Track


@dataclass
class Verdict:
    passed: bool
    stage: str = ""
    reason: str = ""


@dataclass
class ZonePolicy:
    """Per-zone operating policy. This is border doctrine, not vision."""
    criticality: str = "normal"          # "low" | "normal" | "critical"
    curfew_from_hour: Optional[int] = 20
    curfew_to_hour: Optional[int] = 5
    #: True where a free-movement treaty makes daytime crossing lawful,
    #: which is the actual legal situation along the Indo-Nepal border.
    free_movement_daytime: bool = False
    suppress_animals: bool = True


@dataclass
class CascadeStats:
    considered: int = 0
    passed: int = 0
    dropped_by: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    started: float = field(default_factory=time.time)

    @property
    def suppressed(self) -> int:
        return self.considered - self.passed

    def far_per_hour(self, confirmed_true: Optional[int] = None) -> float:
        """Alerts per hour that reached the operator."""
        hours = max((time.time() - self.started) / 3600.0, 1e-6)
        return self.passed / hours

    def as_dict(self) -> dict:
        return {"considered": self.considered, "passed": self.passed,
                "suppressed": self.suppressed,
                "dropped_by": dict(self.dropped_by),
                "alerts_per_hour": round(self.far_per_hour(), 2)}


class FalseAlarmCascade:
    def __init__(self, min_track_hits: int = 4, min_track_seconds: float = 0.3,
                 confirm_of_last: Tuple[int, int] = (3, 5),
                 policies: Optional[Dict[str, ZonePolicy]] = None,
                 default_policy: Optional[ZonePolicy] = None,
                 animal_person_min_ratio: float = 1.25):
        self.min_track_hits = min_track_hits
        self.min_track_seconds = min_track_seconds
        self.confirm_n, self.confirm_of = confirm_of_last
        self.policies = policies or {}
        self.default_policy = default_policy or ZonePolicy()
        self.animal_person_min_ratio = animal_person_min_ratio
        self.stats = CascadeStats()
        self._recent: Dict[int, Deque[str]] = defaultdict(
            lambda: deque(maxlen=self.confirm_of))

    # ------------------------------------------------------------------
    def policy_for(self, event: RuleEvent) -> ZonePolicy:
        zone = str(event.attributes.get("zone", "")) or event.rule_id
        return self.policies.get(zone, self.default_policy)

    def observe(self, track: Track):
        """Feed every frame's classification in, so stage 3 can vote."""
        self._recent[track.track_id].append(track.label)

    # ------------------------------------------------------------------
    def _stage3(self, event: RuleEvent, track: Optional[Track]) -> Verdict:
        if track is None:
            return Verdict(True)
        if track.hits < self.min_track_hits:
            return Verdict(False, "3:temporal",
                           f"track seen {track.hits}x, need {self.min_track_hits}")
        if (track.last_seen - track.first_seen) < self.min_track_seconds:
            return Verdict(False, "3:temporal", "track too short-lived")
        recent = self._recent.get(track.track_id)
        if recent and len(recent) >= self.confirm_of:
            agree = sum(1 for lbl in recent if lbl == track.voted_label)
            if agree < self.confirm_n:
                return Verdict(False, "3:temporal",
                               f"class unstable ({agree}/{len(recent)} frames)")
        return Verdict(True)

    def _stage4(self, event: RuleEvent, track: Optional[Track],
                policy: ZonePolicy) -> Verdict:
        label = event.label
        if policy.suppress_animals and label == ANIMAL:
            return Verdict(False, "4:class",
                           "classified as animal (cattle/stray) -- suppressed")
        if track is not None and label == PERSON and track.width > 0:
            ratio = track.height / track.width
            if ratio < self.animal_person_min_ratio:
                return Verdict(
                    False, "4:class",
                    f"shape ratio {ratio:.2f} is not upright; likely an animal")
        return Verdict(True)

    def _stage5(self, event: RuleEvent, policy: ZonePolicy) -> Verdict:
        hour = time.localtime(event.ts).tm_hour
        night = bool(event.attributes.get("night"))
        curfew = self._in_curfew(hour, policy)

        if policy.free_movement_daytime and not night and not curfew:
            if policy.criticality != "critical" and event.label == PERSON:
                return Verdict(
                    False, "5:context",
                    "daytime movement in a free-movement corridor")
        return Verdict(True)

    @staticmethod
    def _in_curfew(hour: int, policy: ZonePolicy) -> bool:
        a, b = policy.curfew_from_hour, policy.curfew_to_hour
        if a is None or b is None:
            return False
        return (a <= hour or hour < b) if a > b else (a <= hour < b)

    # ------------------------------------------------------------------
    def apply_severity(self, event: RuleEvent, policy: ZonePolicy) -> RuleEvent:
        hour = time.localtime(event.ts).tm_hour
        # The camera outranks the clock. If the sensor is plainly seeing
        # daylight, it is not curfew whatever the hour says -- an appliance
        # with a wrong timezone, a dead RTC after a power cut, or a site
        # commissioned in the wrong locale would otherwise escalate every
        # event of the working day. Frame brightness is ground truth;
        # system time is a configuration file.
        looks_dark = bool(event.attributes.get("night", True))
        if policy.criticality == "critical":
            event.severity = escalate(event.severity)
        elif policy.criticality == "low":
            idx = max(0, [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                          Severity.HIGH, Severity.CRITICAL].index(event.severity) - 1)
            event.severity = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                              Severity.HIGH, Severity.CRITICAL][idx]
        if looks_dark and self._in_curfew(hour, policy):
            event.severity = escalate(event.severity)
            event.attributes["curfew"] = True
        return event

    def filter(self, event: RuleEvent,
               track: Optional[Track] = None) -> Tuple[bool, Verdict]:
        self.stats.considered += 1
        policy = self.policy_for(event)
        # Tamper bypasses the cascade: it is about the camera, not a track,
        # and suppressing it would hide the very attack it detects.
        if event.rule_type == "tamper":
            self.stats.passed += 1
            return True, Verdict(True, "bypass", "tamper is never suppressed")
        for stage in (self._stage3(event, track),
                      self._stage4(event, track, policy),
                      self._stage5(event, policy)):
            if not stage.passed:
                self.stats.dropped_by[stage.stage] += 1
                return False, stage
        self.apply_severity(event, policy)
        self.stats.passed += 1
        return True, Verdict(True, "5:context", "passed all stages")

    def forget(self, track_id: int):
        self._recent.pop(track_id, None)
