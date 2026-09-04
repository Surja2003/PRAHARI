"""Ground-plane geometry and the rule engine (PS capabilities 05, 06, 07).

Two things separate this from a toy tripwire.

Homography. The operator marks four points of known spacing once, and from
then on dwell is in seconds, speed is in km/h and zone size is in metres.
Rules become portable between cameras and alert text becomes meaningful:
"loitered 4 minutes within 20 m of pillar 7" rather than "box in polygon".

Direction. Crossings are evaluated on the foot point and are directional.
On an open border with a free-movement treaty, India-bound and Nepal-bound
are different events with different severities -- direction IS the
intelligence.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

import cv2
import numpy as np

from .track import Track

Point = Tuple[float, float]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
          Severity.CRITICAL]


def escalate(sev: Severity, steps: int = 1) -> Severity:
    i = min(len(_ORDER) - 1, _ORDER.index(sev) + steps)
    return _ORDER[i]


# --------------------------------------------------------------------------
# ground plane
# --------------------------------------------------------------------------

@dataclass
class GroundPlane:
    """Image <-> ground homography from four surveyed points."""
    image_points: List[Point] = field(default_factory=list)
    world_points: List[Point] = field(default_factory=list)   # metres
    _H: Optional[np.ndarray] = None

    @property
    def calibrated(self) -> bool:
        return self._H is not None

    def fit(self) -> bool:
        if len(self.image_points) < 4 or len(self.world_points) < 4:
            return False
        src = np.array(self.image_points, np.float32)
        dst = np.array(self.world_points, np.float32)
        H, _ = cv2.findHomography(src, dst, method=0)
        self._H = H
        return H is not None

    def to_ground(self, p: Point) -> Optional[Point]:
        if self._H is None:
            return None
        v = np.array([[p[0], p[1], 1.0]], np.float64).T
        w = self._H @ v
        if abs(w[2, 0]) < 1e-9:
            return None
        return (float(w[0, 0] / w[2, 0]), float(w[1, 0] / w[2, 0]))

    def distance_m(self, a: Point, b: Point) -> Optional[float]:
        ga, gb = self.to_ground(a), self.to_ground(b)
        if ga is None or gb is None:
            return None
        return math.hypot(gb[0] - ga[0], gb[1] - ga[1])


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------

@dataclass
class RuleEvent:
    rule_id: str
    rule_type: str
    camera_id: str
    track_id: int
    label: str
    severity: Severity
    message: str
    ts: float
    box: Tuple[float, float, float, float]
    direction: str = ""
    dwell_s: float = 0.0
    speed_kmh: Optional[float] = None
    ground_m: Optional[Tuple[float, float]] = None
    attributes: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"rule_id": self.rule_id, "rule_type": self.rule_type,
                "camera_id": self.camera_id, "track_id": self.track_id,
                "label": self.label, "severity": self.severity.value,
                "message": self.message, "ts": self.ts,
                "box": [round(v, 1) for v in self.box],
                "direction": self.direction,
                "dwell_s": round(self.dwell_s, 1),
                "speed_kmh": round(self.speed_kmh, 1) if self.speed_kmh else None,
                "ground_m": ([round(v, 2) for v in self.ground_m]
                             if self.ground_m else None),
                "attributes": self.attributes}


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

class Rule:
    rule_type = "rule"

    def __init__(self, rule_id: str, name: str = "",
                 severity: Severity = Severity.MEDIUM,
                 labels: Optional[Sequence[str]] = None,
                 night_severity_bump: int = 1):
        self.rule_id = rule_id
        self.name = name or rule_id
        self.severity = severity
        self.labels = set(labels) if labels else None
        self.night_severity_bump = night_severity_bump

    def applies(self, track: Track) -> bool:
        return self.labels is None or track.voted_label in self.labels

    def evaluate(self, track: Track, ctx: "RuleContext") -> List[RuleEvent]:
        return []

    def _sev(self, ctx: "RuleContext") -> Severity:
        if ctx.is_night and self.night_severity_bump:
            return escalate(self.severity, self.night_severity_bump)
        return self.severity


@dataclass
class RuleContext:
    camera_id: str
    ts: float
    ground: Optional[GroundPlane] = None
    is_night: bool = False
    fps: float = 15.0

    def speed_kmh(self, track: Track) -> Optional[float]:
        if not self.ground or not self.ground.calibrated or len(track.history) < 4:
            return None
        a, b = track.history[-4], track.history[-1]
        d = self.ground.distance_m(a, b)
        if d is None:
            return None
        dt = 3.0 / max(self.fps, 1e-6)
        return (d / dt) * 3.6


class Tripwire(Rule):
    """Directional line crossing on the foot point (PS capability 05)."""
    rule_type = "tripwire"

    def __init__(self, rule_id: str, a: Point, b: Point,
                 direction: str = "both", names: Tuple[str, str] = ("A", "B"),
                 **kw):
        super().__init__(rule_id, **kw)
        self.a = a
        self.b = b
        self.direction = direction          # "both" | "a_to_b" | "b_to_a"
        self.names = names
        self._side: Dict[int, float] = {}

    def _signed(self, p: Point) -> float:
        return ((self.b[0] - self.a[0]) * (p[1] - self.a[1])
                - (self.b[1] - self.a[1]) * (p[0] - self.a[0]))

    @staticmethod
    def _between(p: Point, a: Point, b: Point) -> bool:
        """Only count crossings that happen across the segment itself."""
        vx, vy = b[0] - a[0], b[1] - a[1]
        L2 = vx * vx + vy * vy
        if L2 <= 1e-9:
            return False
        t = ((p[0] - a[0]) * vx + (p[1] - a[1]) * vy) / L2
        return -0.05 <= t <= 1.05

    def evaluate(self, track: Track, ctx: RuleContext) -> List[RuleEvent]:
        if not self.applies(track):
            return []
        p = track.foot
        s = self._signed(p)
        prev = self._side.get(track.track_id)
        self._side[track.track_id] = s
        if prev is None or prev == 0 or (s > 0) == (prev > 0):
            return []
        if not self._between(p, self.a, self.b):
            return []
        crossed = "a_to_b" if prev < 0 <= s else "b_to_a"
        if self.direction != "both" and crossed != self.direction:
            return []
        heading = self.names[1] if crossed == "a_to_b" else self.names[0]
        speed = ctx.speed_kmh(track)
        ground = ctx.ground.to_ground(p) if ctx.ground else None
        msg = (f"{track.voted_label} crossed {self.name} heading {heading}")
        if speed:
            msg += f" at {speed:.0f} km/h"
        return [RuleEvent(
            self.rule_id, self.rule_type, ctx.camera_id, track.track_id,
            track.voted_label, self._sev(ctx), msg, ctx.ts, track.box,
            direction=crossed, speed_kmh=speed, ground_m=ground,
            attributes={"heading": heading, "night": ctx.is_night})]


class Zone(Rule):
    """Polygon entry plus dwell and loitering (PS capabilities 05, 06)."""
    rule_type = "zone"

    def __init__(self, rule_id: str, polygon: Sequence[Point],
                 dwell_s: float = 0.0, loiter_s: float = 0.0, **kw):
        super().__init__(rule_id, **kw)
        self.polygon = np.array(polygon, np.int32).reshape(-1, 1, 2)
        self.dwell_s = dwell_s
        self.loiter_s = loiter_s
        self._entered: Dict[int, float] = {}
        self._fired: Dict[int, set] = {}

    def contains(self, p: Point) -> bool:
        return cv2.pointPolygonTest(self.polygon, (float(p[0]), float(p[1])),
                                    False) >= 0

    def evaluate(self, track: Track, ctx: RuleContext) -> List[RuleEvent]:
        if not self.applies(track):
            return []
        tid = track.track_id
        inside = self.contains(track.foot)
        if not inside:
            self._entered.pop(tid, None)
            self._fired.pop(tid, None)
            return []

        entered = self._entered.setdefault(tid, ctx.ts)
        fired = self._fired.setdefault(tid, set())
        dwell = ctx.ts - entered
        out: List[RuleEvent] = []
        ground = ctx.ground.to_ground(track.foot) if ctx.ground else None

        def emit(kind: str, sev: Severity, msg: str):
            out.append(RuleEvent(
                f"{self.rule_id}:{kind}", kind, ctx.camera_id, tid,
                track.voted_label, sev, msg, ctx.ts, track.box,
                dwell_s=dwell, ground_m=ground,
                speed_kmh=ctx.speed_kmh(track),
                attributes={"zone": self.name, "night": ctx.is_night}))

        if "entry" not in fired and dwell >= self.dwell_s:
            fired.add("entry")
            emit("zone_entry", self._sev(ctx),
                 f"{track.voted_label} entered {self.name}")
        if self.loiter_s and "loiter" not in fired and dwell >= self.loiter_s:
            fired.add("loiter")
            emit("loitering", escalate(self._sev(ctx)),
                 f"{track.voted_label} loitering in {self.name} "
                 f"for {dwell:.0f}s")
        return out


class NightMovement(Rule):
    """PS capability 07.

    Night is not a harder version of the day problem, it is a different
    policy over the same pipeline: inside a curfew zone after dark, ANY
    confirmed movement is an alert regardless of class.
    """
    rule_type = "night_movement"

    def __init__(self, rule_id: str, polygon: Optional[Sequence[Point]] = None,
                 min_confirm_frames: int = 4, **kw):
        kw.setdefault("severity", Severity.HIGH)
        super().__init__(rule_id, **kw)
        self.polygon = (np.array(polygon, np.int32).reshape(-1, 1, 2)
                        if polygon else None)
        self.min_confirm_frames = min_confirm_frames
        self._fired: set = set()

    def evaluate(self, track: Track, ctx: RuleContext) -> List[RuleEvent]:
        if not ctx.is_night or track.track_id in self._fired:
            return []
        if track.hits < self.min_confirm_frames:
            return []
        if self.polygon is not None:
            p = track.foot
            if cv2.pointPolygonTest(self.polygon,
                                    (float(p[0]), float(p[1])), False) < 0:
                return []
        self._fired.add(track.track_id)
        return [RuleEvent(
            self.rule_id, self.rule_type, ctx.camera_id, track.track_id,
            track.voted_label, self.severity,
            f"night movement in {self.name}: {track.voted_label}",
            ctx.ts, track.box,
            ground_m=ctx.ground.to_ground(track.foot) if ctx.ground else None,
            attributes={"night": True})]


class Tamper:
    """Camera tamper detection: defocus, blackout, repositioning.

    Not a per-track rule -- it looks at the frame itself, which is why it
    catches the failure mode nothing else does: an intruder who covers or
    turns the camera before crossing.
    """
    rule_type = "tamper"

    def __init__(self, rule_id: str = "tamper", blur_ratio: float = 0.35,
                 dark_level: float = 14.0, hist_shift: float = 0.55,
                 grace_frames: int = 45, cooldown_s: float = 180.0):
        self.rule_id = rule_id
        self.name = "camera tamper"
        self.blur_ratio = blur_ratio
        self.dark_level = dark_level
        self.hist_shift = hist_shift
        self.grace_frames = grace_frames
        self.cooldown_s = cooldown_s
        self._baseline_focus: Optional[float] = None
        self._baseline_hist: Optional[np.ndarray] = None
        self._n = 0
        self._last_fire = 0.0

    def evaluate_frame(self, frame: np.ndarray,
                       ctx: RuleContext) -> List[RuleEvent]:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        focus = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        hist = cv2.calcHist([gray], [0], None, [64], [0, 256])
        cv2.normalize(hist, hist)
        self._n += 1

        if self._n <= self.grace_frames:
            self._baseline_focus = (focus if self._baseline_focus is None
                                    else 0.9 * self._baseline_focus + 0.1 * focus)
            self._baseline_hist = (hist if self._baseline_hist is None
                                   else 0.9 * self._baseline_hist + 0.1 * hist)
            return []

        reasons = []
        if self._baseline_focus and focus < self._baseline_focus * self.blur_ratio:
            reasons.append("defocused or covered")
        if float(gray.mean()) < self.dark_level:
            reasons.append("blacked out")
        if self._baseline_hist is not None:
            corr = float(cv2.compareHist(self._baseline_hist, hist,
                                         cv2.HISTCMP_CORREL))
            if corr < self.hist_shift:
                reasons.append("view changed, camera may have been moved")

        if not reasons or (ctx.ts - self._last_fire) < self.cooldown_s:
            # slow baseline drift so lighting changes do not accumulate
            self._baseline_hist = 0.995 * self._baseline_hist + 0.005 * hist
            return []
        self._last_fire = ctx.ts
        h, w = gray.shape[:2]
        return [RuleEvent(
            self.rule_id, self.rule_type, ctx.camera_id, -1, "camera",
            Severity.CRITICAL, "camera tamper: " + "; ".join(reasons),
            ctx.ts, (0.0, 0.0, float(w), float(h)),
            attributes={"reasons": reasons, "focus": round(focus, 1)})]


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, camera_id: str, rules: Optional[List[Rule]] = None,
                 ground: Optional[GroundPlane] = None,
                 tamper: Optional[Tamper] = None, fps: float = 15.0):
        self.camera_id = camera_id
        self.rules = rules or []
        self.ground = ground
        self.tamper = tamper
        self.fps = fps

    def add(self, rule: Rule) -> "RuleEngine":
        self.rules.append(rule)
        return self

    def evaluate(self, tracks: Sequence[Track], frame: Optional[np.ndarray],
                 ts: float, is_night: bool = False) -> List[RuleEvent]:
        ctx = RuleContext(self.camera_id, ts, self.ground, is_night, self.fps)
        events: List[RuleEvent] = []
        for rule in self.rules:
            for t in tracks:
                events.extend(rule.evaluate(t, ctx))
        if self.tamper is not None and frame is not None:
            events.extend(self.tamper.evaluate_frame(frame, ctx))
        return events


def is_night_frame(frame: np.ndarray, sat_threshold: float = 18.0) -> bool:
    """Detect the camera's IR cut-filter switch from the image itself.

    Field cameras flip to infrared twice a day and the picture goes
    monochrome -- saturation collapses. Detecting that from frame
    statistics means night mode (and the IR-tuned weights that go with it)
    needs no configuration and no clock.
    """
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    return float(hsv[:, :, 1].mean()) < sat_threshold
