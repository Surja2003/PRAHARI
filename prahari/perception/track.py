"""ByteTrack-style multi-object tracking.

The idea that makes ByteTrack work is kept: associate high-confidence
detections first, then give the *low*-confidence ones a second chance
against whatever tracks are still unmatched. That second pass is what
keeps an identity alive through a few frames of partial occlusion, which
at a border is the difference between one alert and four.

Motion model is constant-velocity extrapolation rather than a full Kalman
filter, and matching is greedy rather than Hungarian: both are deliberate,
because this has to run on a CPU-only outpost. Swapping in BoT-SORT with
camera-motion compensation is a drop-in replacement at this interface, and
is the Phase 3 upgrade for PTZ cameras.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .detect import Detection, iou

_ids = itertools.count(1)


@dataclass
class Track:
    track_id: int
    label: str
    box: Tuple[float, float, float, float]
    score: float
    hits: int = 1
    age: int = 0
    misses: int = 0
    confirmed: bool = False
    velocity: Tuple[float, float] = (0.0, 0.0)
    history: List[Tuple[float, float]] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    label_votes: Dict[str, float] = field(default_factory=dict)

    # ---------------------------------------------------------------- geometry
    @property
    def foot(self) -> Tuple[float, float]:
        x1, _y1, x2, y2 = self.box
        return ((x1 + x2) / 2.0, y2)

    @property
    def height(self) -> float:
        return self.box[3] - self.box[1]

    @property
    def width(self) -> float:
        return self.box[2] - self.box[0]

    def predicted(self) -> Tuple[float, float, float, float]:
        vx, vy = self.velocity
        x1, y1, x2, y2 = self.box
        return (x1 + vx, y1 + vy, x2 + vx, y2 + vy)

    def as_detection(self) -> Detection:
        return Detection(*self.box, self.score, self.label)

    @property
    def voted_label(self) -> str:
        """Class voted over the whole track, not taken from one frame.

        A vehicle seen over forty frames gives a far more stable answer
        than any single detection, and the same holds for person/animal
        confusion at distance -- which is the main false alarm here.
        """
        if not self.label_votes:
            return self.label
        return max(self.label_votes.items(), key=lambda kv: kv[1])[0]

    def as_dict(self) -> dict:
        return {"track_id": self.track_id, "label": self.voted_label,
                "box": [round(v, 1) for v in self.box],
                "score": round(self.score, 3), "hits": self.hits,
                "age": self.age, "confirmed": self.confirmed,
                "height_px": round(self.height, 1),
                "width_px": round(self.width, 1)}


class ByteTracker:
    def __init__(self, high_thresh: float = 0.5, low_thresh: float = 0.2,
                 match_iou: float = 0.25, max_misses: int = 25,
                 confirm_hits: int = 3):
        self.high = high_thresh
        self.low = low_thresh
        self.match_iou = match_iou
        self.max_misses = max_misses
        self.confirm_hits = confirm_hits
        self.tracks: List[Track] = []

    # ------------------------------------------------------------------
    @staticmethod
    def _greedy(tracks: List[Track], dets: List[Detection],
                thresh: float) -> Tuple[List[Tuple[int, int]], List[int], List[int]]:
        pairs: List[Tuple[float, int, int]] = []
        for ti, t in enumerate(tracks):
            pred = Detection(*t.predicted(), t.score, t.label)
            for di, d in enumerate(dets):
                score = iou(pred, d)
                if score >= thresh:
                    pairs.append((score, ti, di))
        pairs.sort(reverse=True)
        used_t, used_d, matched = set(), set(), []
        for _score, ti, di in pairs:
            if ti in used_t or di in used_d:
                continue
            used_t.add(ti)
            used_d.add(di)
            matched.append((ti, di))
        free_t = [i for i in range(len(tracks)) if i not in used_t]
        free_d = [i for i in range(len(dets)) if i not in used_d]
        return matched, free_t, free_d

    def _update_track(self, t: Track, d: Detection, now: float):
        ox, oy = t.foot
        t.box = d.xyxy()
        nx, ny = t.foot
        # light smoothing keeps the velocity usable for prediction
        t.velocity = (0.6 * t.velocity[0] + 0.4 * (nx - ox),
                      0.6 * t.velocity[1] + 0.4 * (ny - oy))
        t.score = d.score
        t.hits += 1
        t.misses = 0
        t.last_seen = now
        t.label_votes[d.label] = t.label_votes.get(d.label, 0.0) + d.score
        t.label = d.label
        t.history.append((nx, ny))
        if len(t.history) > 240:
            del t.history[:-240]
        if t.hits >= self.confirm_hits:
            t.confirmed = True

    # ------------------------------------------------------------------
    def update(self, detections: Sequence[Detection], now: float) -> List[Track]:
        for t in self.tracks:
            t.age += 1

        high = [d for d in detections if d.score >= self.high]
        low = [d for d in detections
               if self.low <= d.score < self.high]

        # pass 1: confident detections against every track
        matched, free_t, free_high = self._greedy(self.tracks, high,
                                                  self.match_iou)
        for ti, di in matched:
            self._update_track(self.tracks[ti], high[di], now)

        # pass 2: the ByteTrack idea -- weak detections rescue lost tracks
        remaining = [self.tracks[i] for i in free_t]
        matched2, free_t2, _ = self._greedy(remaining, low, self.match_iou)
        rescued = set()
        for ti, di in matched2:
            self._update_track(remaining[ti], low[di], now)
            rescued.add(id(remaining[ti]))

        for t in remaining:
            if id(t) not in rescued:
                t.misses += 1

        # new tracks from unmatched confident detections only
        for di in free_high:
            d = high[di]
            t = Track(track_id=next(_ids), label=d.label, box=d.xyxy(),
                      score=d.score, first_seen=now, last_seen=now)
            t.label_votes[d.label] = d.score
            t.history.append(t.foot)
            self.tracks.append(t)

        self.tracks = [t for t in self.tracks if t.misses <= self.max_misses]
        return [t for t in self.tracks if t.confirmed and t.misses == 0]

    @property
    def active(self) -> List[Track]:
        return [t for t in self.tracks if t.confirmed and t.misses == 0]

    def get(self, track_id: int) -> Optional[Track]:
        for t in self.tracks:
            if t.track_id == track_id:
                return t
        return None
