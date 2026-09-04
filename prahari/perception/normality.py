"""What is normal for THIS camera — learned, unsupervised, per view.

The operator problem this solves: a rule engine fires on everything that
matches a rule, so somebody has to sit and read every alert. That does not
scale to a border, and at 03:00 there is nobody sitting.

The answer is not a better rule. It is a baseline. Every camera watches the
same scene for weeks, so it can learn its own habits without a single label
and without anyone supervising it:

  when      does movement normally happen here, by hour and weekday
  where     in this frame do people and vehicles normally walk
  how fast  do things normally move
  how big   are they normally
  how long  do they normally stay

Anomaly is then a measurable quantity — surprise against that baseline —
rather than a human's opinion. A person crossing the gate at 09:00 scores
near zero. The same person on the same path at 03:12, where nothing has
walked in three weeks, scores high, and the system can act on its own.

Everything here is counting and arithmetic: no training run, no GPU, no
labels. It starts working the day it is installed and gets better on its
own. Until it has seen enough, `mature` is False and the autonomy layer
falls back to rules — a model that has watched a camera for ten minutes
must not be trusted to dismiss anything.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --- maturity: how much evidence before the baseline may be trusted -------
#: A demo runs for minutes, a border outpost for years. The production
#: defaults are deliberately conservative -- a camera watched for ten
#: minutes must not be trusted to dismiss anything -- but a demonstration
#: needs to be able to show the autonomy working, so both are settable.
MIN_OBSERVATIONS = int(os.environ.get("PRAHARI_BASELINE_MIN_OBS", "120"))
MIN_SPAN_HOURS = float(os.environ.get("PRAHARI_BASELINE_MIN_HOURS", "6"))

GRID_COLS = 24
GRID_ROWS = 14

#: Exponential forgetting, applied per day, so a baseline tracks seasons and
#: new patrol habits instead of being frozen at install time.
DAILY_DECAY = 0.985


#: Normaliser: an event this rare counts as maximally surprising.
_RARE = 1e-3
_LOG_RARE = -math.log(_RARE)          # positive, ~6.9


def _surprise(p: float) -> float:
    """Map a probability to 0..1 surprise. p=1 -> 0, p -> 0 gives 1.

    Divide by -log(_RARE), not log(_RARE): the latter is negative and
    silently flips the sign of every score, which makes the rarest events
    look the *least* surprising.
    """
    p = min(max(p, 1e-9), 1.0)
    return max(0.0, min(1.0, -math.log(p) / _LOG_RARE))


@dataclass
class Welford:
    """Streaming mean and variance. Constant memory, no window to tune."""
    n: float = 0.0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, x: float, weight: float = 1.0):
        self.n += weight
        delta = x - self.mean
        self.mean += weight * delta / self.n
        self.m2 += weight * delta * (x - self.mean)

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(max(self.m2 / self.n, 0.0))

    def z(self, x: float) -> float:
        s = self.std
        if self.n < 8 or s <= 1e-6:
            return 0.0
        return abs(x - self.mean) / s

    def decay(self, factor: float):
        self.n *= factor
        self.m2 *= factor

    def as_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: dict) -> "Welford":
        return cls(n=d.get("n", 0.0), mean=d.get("mean", 0.0),
                   m2=d.get("m2", 0.0))


@dataclass
class AnomalyScore:
    """Why something is unusual, not merely that it is."""
    score: float = 0.0
    mature: bool = False
    components: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    observations: int = 0

    def as_dict(self) -> dict:
        return {"score": round(self.score, 3), "mature": self.mature,
                "components": {k: round(v, 3)
                               for k, v in self.components.items()},
                "reasons": self.reasons, "observations": self.observations}


class NormalityModel:
    """One per camera. Cheap to update, cheap to persist, explainable."""

    def __init__(self, camera_id: str):
        self.camera_id = camera_id
        self.lock = threading.Lock()
        # 7 weekdays x 24 hours of track starts
        self.temporal: List[List[float]] = [[0.0] * 24 for _ in range(7)]
        self.grid: List[List[float]] = [[0.0] * GRID_COLS
                                        for _ in range(GRID_ROWS)]
        self.speed = Welford()
        self.size = Welford()
        self.dwell = Welford()
        self.by_class: Dict[str, float] = {}
        self.observations = 0
        self.first_seen = 0.0
        self.last_seen = 0.0
        self._last_decay = time.time()

    # ------------------------------------------------------------------
    @property
    def span_hours(self) -> float:
        if not self.first_seen:
            return 0.0
        return (self.last_seen - self.first_seen) / 3600.0

    @property
    def mature(self) -> bool:
        """Enough evidence to be allowed to influence a decision."""
        return (self.observations >= MIN_OBSERVATIONS
                and self.span_hours >= MIN_SPAN_HOURS)

    def _maybe_decay(self, now: float):
        days = (now - self._last_decay) / 86400.0
        if days < 0.25:
            return
        factor = DAILY_DECAY ** days
        self._last_decay = now
        for row in self.temporal:
            for i in range(24):
                row[i] *= factor
        for row in self.grid:
            for i in range(GRID_COLS):
                row[i] *= factor
        for w in (self.speed, self.size, self.dwell):
            w.decay(factor)
        for k in list(self.by_class):
            self.by_class[k] *= factor

    # ------------------------------------------------------------------
    def observe(self, *, ts: float, label: str, foot_xy: Tuple[float, float],
                frame_wh: Tuple[int, int], height_px: float,
                speed_px_s: float, dwell_s: float):
        """Record one confirmed track. Called for every track, always --
        the baseline must learn from ordinary traffic, which is most of it."""
        with self.lock:
            self._maybe_decay(ts)
            lt = time.localtime(ts)
            self.temporal[lt.tm_wday][lt.tm_hour] += 1.0

            w, h = frame_wh
            if w and h:
                cx = min(GRID_COLS - 1, max(0, int(foot_xy[0] / w * GRID_COLS)))
                cy = min(GRID_ROWS - 1, max(0, int(foot_xy[1] / h * GRID_ROWS)))
                self.grid[cy][cx] += 1.0

            if speed_px_s > 0:
                self.speed.add(speed_px_s)
            if height_px > 0:
                self.size.add(height_px)
            if dwell_s > 0:
                self.dwell.add(dwell_s)
            self.by_class[label] = self.by_class.get(label, 0.0) + 1.0

            self.observations += 1
            # min/max, not first-write/last-write: a store-and-forward flush
            # after an outage replays events out of order, and taking them
            # literally makes the observed span negative.
            self.first_seen = ts if not self.first_seen else min(
                self.first_seen, ts)
            self.last_seen = max(self.last_seen, ts)

    # ------------------------------------------------------------------
    def score(self, *, ts: float, label: str, foot_xy: Tuple[float, float],
              frame_wh: Tuple[int, int], height_px: float,
              speed_px_s: float, dwell_s: float) -> AnomalyScore:
        """How surprising is this, given everything this camera has seen?"""
        with self.lock:
            out = AnomalyScore(mature=self.mature,
                               observations=self.observations)
            if self.observations < 12:
                return out

            total = sum(sum(r) for r in self.temporal) or 1.0
            lt = time.localtime(ts)

            # --- when ---------------------------------------------------
            # Compare this hour against the busiest hour rather than against
            # the mean: what matters is "does anything normally happen here
            # at this time", not the shape of the whole week.
            hour_count = self.temporal[lt.tm_wday][lt.tm_hour]
            busiest = max((max(r) for r in self.temporal), default=0.0) or 1.0
            temporal_p = (hour_count + 0.5) / (busiest + 0.5)
            s_time = _surprise(temporal_p)
            out.components["time_of_day"] = s_time
            if s_time > 0.55:
                out.reasons.append(
                    f"almost nothing normally moves here at "
                    f"{lt.tm_hour:02d}:00")

            # --- where --------------------------------------------------
            w, h = frame_wh
            s_place = 0.0
            if w and h:
                cx = min(GRID_COLS - 1, max(0, int(foot_xy[0] / w * GRID_COLS)))
                cy = min(GRID_ROWS - 1, max(0, int(foot_xy[1] / h * GRID_ROWS)))
                cell = self.grid[cy][cx]
                busiest_cell = max((max(r) for r in self.grid), default=0.0) or 1.0
                s_place = _surprise((cell + 0.5) / (busiest_cell + 0.5))
                out.components["location"] = s_place
                if s_place > 0.6:
                    out.reasons.append("off any path normally used here")

            # --- how fast / how big / how long --------------------------
            z_speed = self.speed.z(speed_px_s) if speed_px_s > 0 else 0.0
            z_size = self.size.z(height_px) if height_px > 0 else 0.0
            z_dwell = self.dwell.z(dwell_s) if dwell_s > 0 else 0.0
            s_speed = min(1.0, z_speed / 4.0)
            s_size = min(1.0, z_size / 4.0)
            s_dwell = min(1.0, z_dwell / 4.0)
            out.components["speed"] = s_speed
            out.components["size"] = s_size
            out.components["dwell"] = s_dwell
            if z_speed > 3:
                out.reasons.append(
                    f"moving {'faster' if speed_px_s > self.speed.mean else 'slower'}"
                    f" than anything normally does here")
            if z_dwell > 3 and dwell_s > self.dwell.mean:
                out.reasons.append("staying far longer than normal")

            # --- what ---------------------------------------------------
            cls_total = sum(self.by_class.values()) or 1.0
            s_class = _surprise((self.by_class.get(label, 0.0) + 0.5)
                                / (cls_total + 0.5))
            out.components["class"] = s_class
            if s_class > 0.7:
                out.reasons.append(f"a {label} is unusual on this camera")

            # Combine by noisy-OR, not by weighted average.
            #
            # Averaging is wrong here: these are independent pieces of
            # evidence for the same conclusion, so two of them agreeing
            # should reinforce, not dilute. Under an average, "nothing has
            # ever moved here at this hour" AND "nothing has ever walked
            # this line" could not exceed the sum of their weights, and a
            # totally unprecedented event capped out around 0.6 -- never
            # enough to act on. Noisy-OR lets concurring evidence compound
            # while a single weak signal still counts for little.
            #
            # The per-component factor is a reliability, not a share: time
            # and place are the two that actually separate an intrusion
            # from the daily routine.
            reliability = (
                (s_time, 0.70), (s_place, 0.65), (s_speed, 0.35),
                (s_dwell, 0.30), (s_class, 0.25), (s_size, 0.20),
            )
            miss = 1.0
            for value, r in reliability:
                miss *= (1.0 - max(0.0, min(1.0, value)) * r)
            out.score = max(0.0, min(1.0, 1.0 - miss))
            return out

    # ------------------------------------------------------------------
    def as_dict(self) -> dict:
        with self.lock:
            return {
                "camera_id": self.camera_id,
                "temporal": self.temporal, "grid": self.grid,
                "speed": self.speed.as_dict(), "size": self.size.as_dict(),
                "dwell": self.dwell.as_dict(), "by_class": self.by_class,
                "observations": self.observations,
                "first_seen": self.first_seen, "last_seen": self.last_seen,
            }

    def summary(self) -> dict:
        with self.lock:
            busiest = (0, 0, 0.0)
            for d, row in enumerate(self.temporal):
                for hh, v in enumerate(row):
                    if v > busiest[2]:
                        busiest = (d, hh, v)
            quiet = [hh for hh in range(24)
                     if sum(self.temporal[d][hh] for d in range(7)) < 1.0]
            return {
                "camera_id": self.camera_id,
                "observations": self.observations,
                "span_hours": round(self.span_hours, 2),
                "mature": self.mature,
                "busiest_hour": busiest[1],
                "quiet_hours": quiet,
                "mean_speed_px_s": round(self.speed.mean, 1),
                "mean_height_px": round(self.size.mean, 1),
                "classes": {k: int(v) for k, v in self.by_class.items()},
            }

    @classmethod
    def from_dict(cls, d: dict) -> "NormalityModel":
        m = cls(d.get("camera_id", "?"))
        m.temporal = d.get("temporal") or m.temporal
        m.grid = d.get("grid") or m.grid
        m.speed = Welford.from_dict(d.get("speed") or {})
        m.size = Welford.from_dict(d.get("size") or {})
        m.dwell = Welford.from_dict(d.get("dwell") or {})
        m.by_class = d.get("by_class") or {}
        m.observations = int(d.get("observations", 0))
        m.first_seen = float(d.get("first_seen", 0.0))
        m.last_seen = float(d.get("last_seen", 0.0))
        return m


class NormalityStore:
    """Keeps one model per camera, on disk.

    Persistence is not a nicety. A baseline that resets on reboot never
    reaches maturity at an outpost that loses power weekly, and the system
    would be permanently stuck in its supervised fallback.
    """

    def __init__(self, path: str = "state/normality.json",
                 autosave_s: float = 120.0):
        self.path = path
        self.autosave_s = autosave_s
        self.models: Dict[str, NormalityModel] = {}
        self._lock = threading.Lock()
        self._last_save = 0.0
        self.load()

    def get(self, camera_id: str) -> NormalityModel:
        with self._lock:
            m = self.models.get(camera_id)
            if m is None:
                m = NormalityModel(camera_id)
                self.models[camera_id] = m
            return m

    def load(self):
        try:
            with open(self.path) as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return
        for cid, d in (raw.get("cameras") or {}).items():
            try:
                self.models[cid] = NormalityModel.from_dict(d)
            except Exception:                                 # noqa: BLE001
                continue

    def save(self, force: bool = False):
        now = time.time()
        if not force and (now - self._last_save) < self.autosave_s:
            return
        self._last_save = now
        with self._lock:
            payload = {"saved": now,
                       "cameras": {cid: m.as_dict()
                                   for cid, m in self.models.items()}}
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def summaries(self) -> List[dict]:
        with self._lock:
            models = list(self.models.values())
        return [m.summary() for m in models]
