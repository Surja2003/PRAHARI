"""Per-camera perception pipeline, plus the evidence ring buffer.

One worker per camera, running in its own thread:

    read -> night check -> detect -> track -> profile optics
         -> rules -> false-alarm cascade -> event + evidence clip

The ring buffer is what makes an alert useful: it holds the last N seconds
continuously, so when a rule fires the clip contains the approach as well
as the crossing. An alert that starts at the moment of detection shows an
operator nothing they can act on.

The watchdog is what makes it survivable: streams drop, and a border
outpost has nobody to press restart.
"""
from __future__ import annotations

import logging
import os
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Sequence

import cv2
import numpy as np

from ..cal.optics import Optics, Role, assess, classify_role
from .cascade import FalseAlarmCascade
from .detect import ANIMAL, PERSON, VEHICLE_CLASSES, Detector, build
from .normality import AnomalyScore, NormalityModel
from .rules import GroundPlane, RuleEngine, RuleEvent, is_night_frame
from .track import ByteTracker, Track

log = logging.getLogger("prahari.perception.worker")

os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp")


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------

class RingBuffer:
    """Rolling frame buffer so evidence clips include the lead-up."""

    def __init__(self, seconds: float = 8.0, fps: float = 15.0):
        self.fps = fps
        self.frames: Deque[tuple] = deque(maxlen=int(seconds * fps) + 2)

    def push(self, frame: np.ndarray, ts: float):
        self.frames.append((ts, frame))

    def clip(self, path: str, pre_s: float = 4.0, post: Sequence = ()) -> Optional[str]:
        if not self.frames:
            return None
        now = self.frames[-1][0]
        chosen = [f for ts, f in self.frames if ts >= now - pre_s]
        chosen.extend(post)
        if not chosen:
            return None
        h, w = chosen[0].shape[:2]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        writer = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"),
                                 self.fps, (w, h))
        if not writer.isOpened():
            return None
        for f in chosen:
            writer.write(f)
        writer.release()
        return path if os.path.exists(path) else None


# --------------------------------------------------------------------------
# rolling optics profiler
# --------------------------------------------------------------------------

class OpticsProfiler:
    """Rolling estimate of what this view can resolve.

    Feeding it confirmed tracks rather than raw detections matters: a
    flickering false positive should not be allowed to talk the camera
    into believing it is a chokepoint.
    """

    def __init__(self, window: int = 400):
        self.person = deque(maxlen=window)
        self.vehicle = deque(maxlen=window)
        self.frame_w = 0
        self.frame_h = 0

    def observe(self, tracks: Sequence[Track], frame_shape):
        self.frame_h, self.frame_w = frame_shape[:2]
        for t in tracks:
            if not t.confirmed:
                continue
            # Never let an implausibly large box set the scale. Capability
            # gating is derived from these numbers, so one frame-sized blob
            # is enough to convince a 400-metre view that it can read
            # number plates.
            if (self.frame_w and t.width > self.frame_w * 0.8) or \
               (self.frame_h and t.height > self.frame_h * 0.9):
                continue
            if t.voted_label == PERSON:
                self.person.append(t.height)
            elif t.voted_label in VEHICLE_CLASSES:
                self.vehicle.append(t.width)

    @staticmethod
    def _pct(values, q: float) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        idx = min(len(s) - 1, max(0, int(q * (len(s) - 1))))
        return float(s[idx])

    def snapshot(self) -> Optics:
        return Optics(
            median_person_px=self._pct(self.person, 0.5),
            p90_person_px=self._pct(self.person, 0.9),
            median_vehicle_w_px=self._pct(self.vehicle, 0.5),
            p90_vehicle_w_px=self._pct(self.vehicle, 0.9),
            samples_person=len(self.person),
            samples_vehicle=len(self.vehicle),
            frame_width=self.frame_w, frame_height=self.frame_h)


# --------------------------------------------------------------------------
# worker
# --------------------------------------------------------------------------

@dataclass
class CameraStatus:
    camera_id: str
    connected: bool = False
    fps: float = 0.0
    frames: int = 0
    reconnects: int = 0
    last_frame_ts: float = 0.0
    is_night: bool = False
    role: str = Role.UNKNOWN.value
    capabilities: Dict[str, bool] = field(default_factory=dict)
    optics: Dict[str, float] = field(default_factory=dict)
    tracks: int = 0
    events: int = 0
    suppressed: int = 0
    error: str = ""

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["fps"] = round(self.fps, 1)
        return d


class CameraWorker(threading.Thread):
    WATCHDOG_S = 8.0

    def __init__(self, camera_id: str, url: str, name: str = "",
                 detector: Optional[Detector] = None,
                 engine: Optional[RuleEngine] = None,
                 cascade: Optional[FalseAlarmCascade] = None,
                 on_event: Optional[Callable[[RuleEvent, dict], None]] = None,
                 evidence_dir: str = "evidence",
                 target_fps: float = 12.0,
                 detector_kind: str = "motion",
                 normality: Optional[NormalityModel] = None):
        super().__init__(daemon=True, name=f"cam-{camera_id}")
        self.camera_id = camera_id
        self.url = url
        self.display_name = name or camera_id
        self.detector = detector or build(detector_kind)
        self.tracker = ByteTracker()
        self.engine = engine or RuleEngine(camera_id)
        self.cascade = cascade or FalseAlarmCascade()
        self.on_event = on_event
        self.evidence_dir = evidence_dir
        self.target_fps = target_fps
        self.profiler = OpticsProfiler()
        # The learned baseline for THIS view. Shared with the server so it
        # can be persisted; a baseline that resets on reboot never matures.
        self.normality = normality or NormalityModel(camera_id)
        self._seen_tracks: Dict[int, float] = {}
        self.ring = RingBuffer(seconds=8.0, fps=target_fps)
        self.status = CameraStatus(camera_id=camera_id)
        self._stop = threading.Event()
        self._latest: Optional[np.ndarray] = None
        self._latest_lock = threading.Lock()
        # Pre-rendered preview. Encoding once per frame here, rather than
        # once per HTTP request, decouples the cost of the video wall from
        # how many browsers are watching it. Downscale BEFORE drawing so the
        # annotation runs on a small image.
        self.preview_width = int(os.environ.get("PRAHARI_PREVIEW_W", "480"))
        self.preview_fps = float(os.environ.get("PRAHARI_PREVIEW_FPS", "6"))
        self._preview: Optional[bytes] = None
        self._preview_lock = threading.Lock()
        self._preview_due = 0.0
        self._night_votes: Deque[bool] = deque(maxlen=45)

    # ------------------------------------------------------------------
    def stop(self):
        self._stop.set()

    def snapshot(self) -> Optional[np.ndarray]:
        with self._latest_lock:
            return None if self._latest is None else self._latest.copy()

    def preview(self) -> Optional[bytes]:
        """Latest annotated preview as JPEG bytes, or None before first frame."""
        with self._preview_lock:
            return self._preview

    # ------------------------------------------------------------------
    def _render_preview(self, frame: np.ndarray):
        h, w = frame.shape[:2]
        scale = min(1.0, self.preview_width / float(w)) if w else 1.0
        small = (cv2.resize(frame, (int(w * scale), max(1, int(h * scale))),
                            interpolation=cv2.INTER_AREA)
                 if scale < 1.0 else frame.copy())

        for rule in getattr(self.engine, "rules", []):
            pts = getattr(rule, "a", None)
            if pts is not None and hasattr(rule, "b"):
                cv2.line(small,
                         (int(rule.a[0] * scale), int(rule.a[1] * scale)),
                         (int(rule.b[0] * scale), int(rule.b[1] * scale)),
                         (0, 165, 255), 2)
            poly = getattr(rule, "polygon", None)
            if poly is not None:
                cv2.polylines(small, [(poly.reshape(-1, 2) * scale)
                                      .astype(np.int32)], True, (80, 200, 160), 2)

        for t in self.tracker.active:
            x1, y1, x2, y2 = (int(v * scale) for v in t.box)
            colour = ((60, 220, 120) if t.voted_label == PERSON
                      else (200, 180, 60))
            cv2.rectangle(small, (x1, y1), (x2, y2), colour, 2)
            cv2.putText(small, f"{t.voted_label} #{t.track_id}",
                        (x1, max(11, y1 - 4)), cv2.FONT_HERSHEY_SIMPLEX,
                        0.38, colour, 1, cv2.LINE_AA)

        label = (f"{self.display_name}  {self.status.fps:.0f} fps  "
                 f"{self.status.role}")
        if self.status.is_night:
            label += "  NIGHT"
        cv2.putText(small, label, (6, 15), cv2.FONT_HERSHEY_SIMPLEX, 0.4,
                    (240, 240, 240), 1, cv2.LINE_AA)

        ok, buf = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 68])
        if ok:
            with self._preview_lock:
                self._preview = buf.tobytes()

    # ------------------------------------------------------------------
    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            cap = cv2.VideoCapture(self.url, cv2.CAP_FFMPEG)
            try:
                cap.set(cv2.CAP_PROP_BUFFERSIZE, 2)
            except Exception:
                pass
            if not cap.isOpened():
                self.status.connected = False
                self.status.error = "cannot open stream"
                self.status.reconnects += 1
                cap.release()
                # exponential backoff -- a downed backhaul must not be
                # hammered, it will come back on its own schedule
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue

            self.status.connected = True
            self.status.error = ""
            backoff = 1.0
            try:
                self._loop(cap)
            except Exception as exc:                          # noqa: BLE001
                log.exception("worker %s failed", self.camera_id)
                self.status.error = f"{exc.__class__.__name__}: {exc}"
            finally:
                cap.release()
            self.status.connected = False
            if not self._stop.is_set():
                self.status.reconnects += 1
                self._stop.wait(1.0)

    # ------------------------------------------------------------------
    def _loop(self, cap: cv2.VideoCapture):
        last_ok = time.time()
        tick = deque(maxlen=30)
        min_dt = 1.0 / max(self.target_fps, 1e-6)
        next_due = time.monotonic()

        while not self._stop.is_set():
            ok, frame = cap.read()
            now = time.time()
            if not ok or frame is None:
                if now - last_ok > self.WATCHDOG_S:
                    self.status.error = "watchdog: no frames"
                    return
                time.sleep(0.05)
                continue
            last_ok = now
            tick.append(now)
            if len(tick) > 2:
                span = tick[-1] - tick[0]
                self.status.fps = (len(tick) - 1) / span if span > 0 else 0.0
            self.status.frames += 1
            self.status.last_frame_ts = now

            with self._latest_lock:
                self._latest = frame
            self.ring.push(frame, now)

            if self.preview_fps > 0 and now >= self._preview_due:
                self._preview_due = now + 1.0 / self.preview_fps
                try:
                    self._render_preview(frame)
                except Exception:
                    log.debug("preview render failed", exc_info=True)

            # frame-rate governor: keep the decode loop draining the socket
            # but only run inference at the target rate
            if time.monotonic() < next_due:
                continue
            next_due = time.monotonic() + min_dt

            self._process(frame, now)

    # ------------------------------------------------------------------
    def _process(self, frame: np.ndarray, now: float):
        self._night_votes.append(is_night_frame(frame))
        night = sum(self._night_votes) > len(self._night_votes) * 0.6
        self.status.is_night = night

        detections = self.detector.detect(frame)
        tracks = self.tracker.update(detections, now)
        for t in tracks:
            self.cascade.observe(t)
        self.status.tracks = len(tracks)

        self.profiler.observe(tracks, frame.shape)
        optics = self.profiler.snapshot()
        self.status.role = classify_role(optics).value
        self.status.capabilities = {v.capability.value: v.enabled
                                    for v in assess(optics)}
        self.status.optics = optics.as_dict()

        self._learn(tracks, frame.shape, now)
        events = self.engine.evaluate(tracks, frame, now, is_night=night)
        by_id = {t.track_id: t for t in tracks}
        for ev in events:
            track = by_id.get(ev.track_id)
            passed, verdict = self.cascade.filter(ev, track)
            if not passed:
                self.status.suppressed += 1
                log.debug("[%s] suppressed at %s: %s",
                          self.camera_id, verdict.stage, verdict.reason)
                continue
            self.status.events += 1
            self._pending_context = {
                "anomaly": (self.anomaly_for(track, now).as_dict()
                            if track else {}),
                "track_quality": self.track_quality(track) if track else {},
            }
            self._emit(ev, frame)

    # ------------------------------------------------------------------
    def _track_speed(self, t: Track) -> float:
        if len(t.history) < 3:
            return 0.0
        (x0, y0), (x1, y1) = t.history[-3], t.history[-1]
        dt = 2.0 / max(self.status.fps or self.target_fps, 1e-6)
        return float(((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5 / dt)

    def _learn(self, tracks: Sequence[Track], shape, now: float):
        """Every confirmed track teaches the baseline what normal is.

        This runs on ordinary traffic, which is nearly all of it -- that is
        the point. Nobody labels anything; the camera simply notices its
        own habits.
        """
        h, w = shape[:2]
        for t in tracks:
            if not t.confirmed:
                continue
            first = self._seen_tracks.setdefault(t.track_id, now)
            self.normality.observe(
                ts=now, label=t.voted_label, foot_xy=t.foot,
                frame_wh=(w, h), height_px=t.height,
                speed_px_s=self._track_speed(t), dwell_s=now - first)
        if len(self._seen_tracks) > 2000:
            cutoff = now - 600
            self._seen_tracks = {k: v for k, v in self._seen_tracks.items()
                                 if v > cutoff}

    def anomaly_for(self, t: Track, now: float) -> AnomalyScore:
        return self.normality.score(
            ts=now, label=t.voted_label, foot_xy=t.foot,
            frame_wh=(self.profiler.frame_w, self.profiler.frame_h),
            height_px=t.height, speed_px_s=self._track_speed(t),
            dwell_s=now - self._seen_tracks.get(t.track_id, now))

    @staticmethod
    def track_quality(t: Track) -> dict:
        votes = t.label_votes or {}
        total = sum(votes.values()) or 1.0
        return {"hits": t.hits, "score": t.score,
                "class_stability": max(votes.values(), default=0.0) / total,
                "age": t.age}

    def _emit(self, ev: RuleEvent, frame: np.ndarray):
        meta = {"camera_name": self.display_name,
                "role": self.status.role,
                "detector": self.detector.name,
                "optics": self.status.optics,
                "capabilities": self.status.capabilities}
        meta.update(getattr(self, "_pending_context", {}) or {})
        clip = os.path.join(
            self.evidence_dir, self.camera_id,
            f"{int(ev.ts)}_{ev.rule_type}_{ev.track_id}.mp4")
        try:
            saved = self.ring.clip(clip, pre_s=4.0)
            if saved:
                meta["evidence_clip"] = saved
        except Exception:
            log.exception("evidence clip failed")
        thumb = clip.replace(".mp4", ".jpg")
        try:
            os.makedirs(os.path.dirname(thumb), exist_ok=True)
            annotated = frame.copy()
            x1, y1, x2, y2 = (int(v) for v in ev.box)
            cv2.rectangle(annotated, (x1, y1), (x2, y2), (0, 165, 255), 2)
            cv2.putText(annotated, f"{ev.label} #{ev.track_id}", (x1, max(14, y1 - 6)),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 165, 255), 1, cv2.LINE_AA)
            if cv2.imwrite(thumb, annotated):
                meta["thumbnail"] = thumb
        except Exception:
            log.exception("thumbnail failed")

        if self.on_event:
            try:
                self.on_event(ev, meta)
            except Exception:
                log.exception("event callback failed")
