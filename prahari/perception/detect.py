"""Detection backends.

One interface, three implementations, chosen by what the box can run:

  YoloDetector    YOLO26/YOLO11 via ultralytics. The production path.
                  Trains on Kaggle, distils to -s, exports TensorRT FP16.
  MotionDetector  MOG2 background subtraction with size/aspect
                  classification. No weights, no GPU, no download. This is
                  the CPU-only fallback named in the plan for an outpost
                  with no accelerator -- and it is what lets the whole
                  pipeline be exercised offline.
  HogDetector     OpenCV's bundled HOG people detector. Slow, but a real
                  learned model with zero download, useful as a check.

Everything downstream consumes Detection objects and never learns which
backend produced them.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import cv2
import numpy as np

log = logging.getLogger("prahari.perception.detect")

# The taxonomy that matters at this border, not COCO's.
PERSON = "person"
VEHICLE_CLASSES = ("two_wheeler", "car", "tempo", "truck", "bus", "tractor",
                   "cart", "boat")
ANIMAL = "animal"
PLATE = "plate"


@dataclass
class Detection:
    x1: float
    y1: float
    x2: float
    y2: float
    score: float
    label: str

    @property
    def width(self) -> float:
        return max(0.0, self.x2 - self.x1)

    @property
    def height(self) -> float:
        return max(0.0, self.y2 - self.y1)

    @property
    def area(self) -> float:
        return self.width * self.height

    @property
    def foot(self) -> Tuple[float, float]:
        """Bottom-centre: where the object meets the ground.

        Rules evaluate on this, never the centroid -- a centroid crosses a
        line while the person's feet are still on the safe side.
        """
        return ((self.x1 + self.x2) / 2.0, self.y2)

    @property
    def centroid(self) -> Tuple[float, float]:
        return ((self.x1 + self.x2) / 2.0, (self.y1 + self.y2) / 2.0)

    def xyxy(self) -> Tuple[float, float, float, float]:
        return (self.x1, self.y1, self.x2, self.y2)

    def as_dict(self) -> dict:
        return {"box": [round(v, 1) for v in self.xyxy()],
                "score": round(self.score, 3), "label": self.label}


class Detector:
    name = "base"

    def detect(self, frame: np.ndarray) -> List[Detection]:
        raise NotImplementedError

    def warmup(self, frame: np.ndarray) -> None:
        pass


# --------------------------------------------------------------------------
# motion backend
# --------------------------------------------------------------------------

class MotionDetector(Detector):
    """Background subtraction plus geometric classification.

    Stage 1 of the false-alarm cascade is a motion gate anyway, so this
    backend is that gate promoted to a detector. Classification is by
    aspect ratio and size, which is crude but genuinely separates upright
    people from wide vehicles, and it costs nothing.
    """
    name = "motion"

    def __init__(self, min_area: int = 60, history: int = 300,
                 var_threshold: float = 24.0, learning_rate: float = 0.004,
                 warmup_frames: int = 20, max_frame_fraction: float = 0.35):
        self.bg = cv2.createBackgroundSubtractorMOG2(
            history=history, varThreshold=var_threshold, detectShadows=False)
        self.min_area = min_area
        self.learning_rate = learning_rate
        self.warmup_frames = warmup_frames
        # A blob covering a third of the frame is not an object. It is a
        # cloud crossing the sun, an IR illuminator switching, or a cut in
        # the source. Left unfiltered it becomes a "vehicle" as wide as the
        # frame, which then tells the optics profiler this camera can read
        # number plates.
        self.max_frame_fraction = max_frame_fraction
        self._seen = 0
        self._kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        self._kernel_big = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (7, 7))

    def warmup(self, frame: np.ndarray) -> None:
        self.bg.apply(frame, learningRate=0.05)
        self._seen += 1

    @staticmethod
    def _classify(w: float, h: float) -> Tuple[str, float]:
        if h <= 0 or w <= 0:
            return PERSON, 0.3
        ratio = h / w
        if ratio >= 1.35:
            return PERSON, min(0.95, 0.55 + 0.12 * ratio)
        if ratio <= 0.75:
            return "car", min(0.9, 0.5 + 0.5 * (1.0 - ratio))
        return ANIMAL, 0.45

    def detect(self, frame: np.ndarray) -> List[Detection]:
        self._seen += 1
        mask = self.bg.apply(frame, learningRate=self.learning_rate)
        if self._seen < self.warmup_frames:
            return []
        _, mask = cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, self._kernel)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, self._kernel_big)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL,
                                       cv2.CHAIN_APPROX_SIMPLE)
        fh, fw = frame.shape[:2]
        frame_area = float(fh * fw) or 1.0
        out: List[Detection] = []
        for c in contours:
            area = cv2.contourArea(c)
            if area < self.min_area or area > frame_area * self.max_frame_fraction:
                continue
            x, y, w, h = cv2.boundingRect(c)
            if w > fw * 0.85 or h > fh * 0.85:
                continue        # spans the view: a scene change, not a thing
            label, score = self._classify(w, h)
            out.append(Detection(float(x), float(y), float(x + w),
                                 float(y + h), score, label))
        out.sort(key=lambda d: d.area, reverse=True)
        return out[:64]


# --------------------------------------------------------------------------
# HOG backend
# --------------------------------------------------------------------------

class HogDetector(Detector):
    """OpenCV's bundled HOG + linear SVM pedestrian detector."""
    name = "hog"

    def __init__(self, scale: float = 1.06, min_person_px: int = 48):
        self.hog = cv2.HOGDescriptor()
        self.hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
        self.scale = scale
        self.min_person_px = min_person_px

    def detect(self, frame: np.ndarray) -> List[Detection]:
        rects, weights = self.hog.detectMultiScale(
            frame, winStride=(8, 8), padding=(8, 8), scale=self.scale)
        out = []
        for (x, y, w, h), score in zip(rects, weights):
            if h < self.min_person_px:
                continue
            out.append(Detection(float(x), float(y), float(x + w),
                                 float(y + h), float(score), PERSON))
        return out


# --------------------------------------------------------------------------
# YOLO backend (production)
# --------------------------------------------------------------------------

#: COCO ids -> the Prahari taxonomy. Retrain on the border taxonomy in P2;
#: until then this maps a stock checkpoint onto the classes we reason about.
COCO_MAP = {
    0: PERSON, 1: "two_wheeler", 2: "car", 3: "two_wheeler", 5: "bus",
    7: "truck", 8: "boat", 15: ANIMAL, 16: ANIMAL, 17: ANIMAL, 18: ANIMAL,
    19: ANIMAL, 20: ANIMAL, 21: ANIMAL, 22: ANIMAL, 23: ANIMAL,
}


class YoloDetector(Detector):
    """Ultralytics backend. Prefers YOLO26 (NMS-free, STAL small-target
    label assignment); falls back to whatever checkpoint is provided.

    Deployment note: export to TensorRT FP16 for the RTX 4050 --
        yolo export model=yolo26s.pt format=engine half=True imgsz=1280
    and pass the resulting .engine as `weights`.
    """
    name = "yolo"

    def __init__(self, weights: str = "yolo26s.pt", imgsz: int = 1280,
                 conf: float = 0.25, iou: float = 0.5, device: str = "",
                 classes: Optional[Dict[int, str]] = None,
                 half: bool = True):
        try:
            from ultralytics import YOLO           # noqa: PLC0415
        except ImportError as exc:                 # pragma: no cover
            raise RuntimeError(
                "ultralytics is not installed. `pip install ultralytics`, or "
                "run with PRAHARI_DETECTOR=motion for the CPU fallback."
            ) from exc
        self.model = YOLO(weights)
        self.imgsz = imgsz
        self.conf = conf
        self.iou = iou
        self.device = device or None
        self.half = half
        self.class_map = classes or COCO_MAP

    def detect(self, frame: np.ndarray) -> List[Detection]:
        res = self.model.predict(
            frame, imgsz=self.imgsz, conf=self.conf, iou=self.iou,
            device=self.device, half=self.half, verbose=False)[0]
        out: List[Detection] = []
        if res.boxes is None:
            return out
        names = getattr(res, "names", {}) or {}
        for box in res.boxes:
            cls = int(box.cls.item())
            label = self.class_map.get(cls) or names.get(cls, f"class_{cls}")
            x1, y1, x2, y2 = (float(v) for v in box.xyxy[0].tolist())
            out.append(Detection(x1, y1, x2, y2, float(box.conf.item()), label))
        return out


# --------------------------------------------------------------------------
# tiled inference (long-range targets)
# --------------------------------------------------------------------------

class MotionGatedTiles(Detector):
    """Motion-gated SAHI: slice only where something moved.

    Blanket tiled inference costs 10-20x a full-frame pass. Running the
    background subtractor first and slicing only the tiles it flags keeps
    nearly all of the small-object recall for a fraction of the compute.
    This is the long-range trick from the plan, and it wraps any detector.
    """
    name = "tiled"

    def __init__(self, inner: Detector, tile: int = 640, overlap: float = 0.2,
                 min_motion_px: int = 40, max_tiles: int = 6):
        self.inner = inner
        self.tile = tile
        self.overlap = overlap
        self.min_motion_px = min_motion_px
        self.max_tiles = max_tiles
        self.bg = cv2.createBackgroundSubtractorMOG2(
            history=200, varThreshold=32, detectShadows=False)
        self.tiles_run = 0
        self.tiles_possible = 0

    def _grid(self, w: int, h: int):
        step = int(self.tile * (1 - self.overlap))
        for y in range(0, max(h - self.tile, 0) + 1, step):
            for x in range(0, max(w - self.tile, 0) + 1, step):
                yield x, y, min(x + self.tile, w), min(y + self.tile, h)

    def detect(self, frame: np.ndarray) -> List[Detection]:
        h, w = frame.shape[:2]
        mask = self.bg.apply(frame, learningRate=0.004)
        _, mask = cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)

        scored = []
        for (x1, y1, x2, y2) in self._grid(w, h):
            self.tiles_possible += 1
            motion = int(cv2.countNonZero(mask[y1:y2, x1:x2]))
            if motion >= self.min_motion_px:
                scored.append((motion, x1, y1, x2, y2))
        scored.sort(reverse=True)

        out: List[Detection] = []
        for _, x1, y1, x2, y2 in scored[:self.max_tiles]:
            self.tiles_run += 1
            for d in self.inner.detect(frame[y1:y2, x1:x2]):
                out.append(Detection(d.x1 + x1, d.y1 + y1, d.x2 + x1,
                                     d.y2 + y1, d.score, d.label))
        return nms(out, 0.55)

    @property
    def savings(self) -> float:
        if not self.tiles_possible:
            return 0.0
        return 1.0 - (self.tiles_run / self.tiles_possible)


def iou(a: Detection, b: Detection) -> float:
    ix1, iy1 = max(a.x1, b.x1), max(a.y1, b.y1)
    ix2, iy2 = min(a.x2, b.x2), min(a.y2, b.y2)
    iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
    inter = iw * ih
    union = a.area + b.area - inter
    return inter / union if union > 0 else 0.0


def nms(dets: Sequence[Detection], thresh: float = 0.5) -> List[Detection]:
    keep: List[Detection] = []
    for d in sorted(dets, key=lambda d: d.score, reverse=True):
        if all(iou(d, k) < thresh or d.label != k.label for k in keep):
            keep.append(d)
    return keep


# --------------------------------------------------------------------------
# factory
# --------------------------------------------------------------------------

def build(kind: str = "motion", **kwargs) -> Detector:
    kind = (kind or "motion").lower()
    if kind == "yolo":
        return YoloDetector(**kwargs)
    if kind == "hog":
        return HogDetector(**kwargs)
    if kind == "tiled":
        inner = build(kwargs.pop("inner", "motion"))
        return MotionGatedTiles(inner, **kwargs)
    return MotionDetector(**kwargs)
