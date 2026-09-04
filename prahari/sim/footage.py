"""Synthetic border footage generator.

Produces the H.264 Annex-B elementary streams the DVR simulator serves.
Two scene types, matching the two camera roles in the plan:

  perimeter  wide view of open ground, a person crossing the line at
             distance (small pixel height -- the real border problem)
  chokepoint gate view, a vehicle approaching with a readable number plate

Replace these with real recordings the moment you have any: this exists so
the pipeline can be exercised end to end with zero external assets.
"""
from __future__ import annotations

import math
import os
import subprocess
from dataclasses import dataclass

import cv2
import numpy as np


@dataclass
class SceneSpec:
    name: str
    kind: str            # "perimeter" | "chokepoint"
    width: int = 1280
    height: int = 720
    fps: int = 15
    seconds: int = 20
    night: bool = False


# --------------------------------------------------------------------------
# drawing helpers
# --------------------------------------------------------------------------

def _ground(w: int, h: int, night: bool) -> np.ndarray:
    """Static background: sky, treeline, open ground, a track."""
    img = np.zeros((h, w, 3), np.uint8)
    horizon = int(h * 0.38)

    sky = (38, 34, 30) if night else (150, 140, 125)
    grd = (26, 30, 26) if night else (86, 104, 74)
    for y in range(h):
        if y < horizon:
            k = y / max(horizon, 1)
            img[y, :] = [int(c * (0.75 + 0.25 * k)) for c in sky]
        else:
            k = (y - horizon) / max(h - horizon, 1)
            img[y, :] = [int(c * (0.72 + 0.5 * k)) for c in grd]

    # treeline along the horizon
    rng = np.random.default_rng(7)
    tree = (18, 26, 18) if night else (44, 62, 40)
    x = 0
    while x < w:
        tw = int(rng.integers(18, 52))
        th = int(rng.integers(14, 46))
        cv2.ellipse(img, (x + tw // 2, horizon), (tw // 2, th), 0, 180, 360, tree, -1)
        x += tw - 6

    # dirt track running away from the camera
    track = (60, 66, 78) if night else (128, 132, 140)
    pts = np.array([[int(w * 0.44), horizon], [int(w * 0.52), horizon],
                    [int(w * 0.78), h], [int(w * 0.12), h]], np.int32)
    cv2.fillPoly(img, [pts], track)
    return img


def _person(img, cx: int, foot_y: int, ph: int, phase: float, night: bool):
    """A crude but correctly-proportioned walking figure."""
    if ph < 6:
        return
    col = (176, 176, 172) if night else (58, 54, 74)
    head_r = max(1, int(ph * 0.11))
    head_y = foot_y - ph + head_r
    body_top = head_y + head_r
    body_bot = foot_y - int(ph * 0.42)
    hw = max(1, int(ph * 0.14))

    cv2.circle(img, (cx, head_y), head_r, col, -1)
    cv2.rectangle(img, (cx - hw, body_top), (cx + hw, body_bot), col, -1)

    swing = math.sin(phase) * ph * 0.15
    lw = max(1, int(ph * 0.07))
    cv2.line(img, (cx, body_bot), (int(cx + swing), foot_y), col, lw)
    cv2.line(img, (cx, body_bot), (int(cx - swing), foot_y), col, lw)
    aw = max(1, int(ph * 0.05))
    arm_y = body_top + int(ph * 0.12)
    cv2.line(img, (cx, arm_y), (int(cx - swing * 0.7), body_bot), col, aw)
    cv2.line(img, (cx, arm_y), (int(cx + swing * 0.7), body_bot), col, aw)


def _plate(w: int, h: int, text: str) -> np.ndarray:
    """A retro-reflective-looking Indian plate."""
    p = np.full((h, w, 3), 236, np.uint8)
    cv2.rectangle(p, (0, 0), (w - 1, h - 1), (28, 28, 28), max(1, h // 14))
    scale = h / 34.0
    cv2.putText(p, text, (int(w * 0.05), int(h * 0.74)),
                cv2.FONT_HERSHEY_DUPLEX, scale, (18, 18, 18), max(1, int(scale * 1.6)),
                cv2.LINE_AA)
    return p


def _vehicle(img, cx: int, base_y: int, vw: int, plate_text: str, night: bool):
    body = (44, 52, 66) if night else (58, 74, 96)
    vh = int(vw * 0.72)
    top = base_y - vh
    cv2.rectangle(img, (cx - vw // 2, top + int(vh * 0.34)),
                  (cx + vw // 2, base_y), body, -1)
    cv2.rectangle(img, (cx - int(vw * 0.32), top),
                  (cx + int(vw * 0.32), top + int(vh * 0.36)), body, -1)
    # windscreen
    cv2.rectangle(img, (cx - int(vw * 0.27), top + int(vh * 0.05)),
                  (cx + int(vw * 0.27), top + int(vh * 0.32)), (30, 34, 40), -1)
    # headlamps
    lamp = (210, 226, 244) if night else (150, 160, 170)
    r = max(2, vw // 22)
    cv2.circle(img, (cx - int(vw * 0.36), base_y - int(vh * 0.28)), r, lamp, -1)
    cv2.circle(img, (cx + int(vw * 0.36), base_y - int(vh * 0.28)), r, lamp, -1)

    pw = int(vw * 0.44)
    phh = max(8, int(pw * 0.24))
    plate = _plate(pw, phh, plate_text)
    y0 = base_y - int(vh * 0.20)
    x0 = cx - pw // 2
    if 0 <= y0 and y0 + phh < img.shape[0] and 0 <= x0 and x0 + pw < img.shape[1]:
        img[y0:y0 + phh, x0:x0 + pw] = plate


def _grain(img, night: bool, rng):
    amp = 10 if night else 4
    noise = rng.normal(0, amp, img.shape).astype(np.int16)
    return np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)


# --------------------------------------------------------------------------
# scene rendering
# --------------------------------------------------------------------------

def render_frames(spec: SceneSpec):
    w, h = spec.width, spec.height
    total = spec.fps * spec.seconds
    bg = _ground(w, h, spec.night)
    rng = np.random.default_rng(11)
    horizon = int(h * 0.38)

    for i in range(total):
        t = i / spec.fps
        img = bg.copy()

        # foliage sway, the classic false-positive source
        sway = int(2 * math.sin(t * 2.1))
        if sway:
            strip = img[horizon - 24:horizon + 6, :].copy()
            img[horizon - 24:horizon + 6, :] = np.roll(strip, sway, axis=1)

        if spec.kind == "perimeter":
            # one person walking left to right, far away (small pixel height)
            frac = (t / spec.seconds)
            cx = int(w * (0.06 + 0.88 * frac))
            foot = int(horizon + (h - horizon) * 0.34)
            ph = int(h * 0.075)                     # ~54 px tall at 720p
            _person(img, cx, foot, ph, t * 7.0, spec.night)

            # a second person, closer, entering later
            if t > spec.seconds * 0.45:
                f2 = (t - spec.seconds * 0.45) / (spec.seconds * 0.55)
                cx2 = int(w * (0.92 - 0.7 * f2))
                foot2 = int(horizon + (h - horizon) * 0.72)
                _person(img, cx2, foot2, int(h * 0.16), t * 6.2 + 1.4, spec.night)

        else:  # chokepoint
            frac = min(1.0, t / (spec.seconds * 0.72))
            base = int(horizon + (h - horizon) * (0.18 + 0.74 * frac))
            vw = int(w * (0.07 + 0.30 * frac))       # grows as it approaches
            _vehicle(img, int(w * 0.5), base, vw, "WB 74 AB 1234", spec.night)
            if t > spec.seconds * 0.55:
                fp = (t - spec.seconds * 0.55) / (spec.seconds * 0.45)
                _person(img, int(w * (0.16 + 0.2 * fp)),
                        int(h * 0.88), int(h * 0.30), t * 6.5, spec.night)

        yield _grain(img, spec.night, rng)


def encode(spec: SceneSpec, out_path: str) -> str:
    """Render the scene and encode to an H.264 Annex-B elementary stream."""
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
        "-f", "rawvideo", "-pix_fmt", "bgr24",
        "-s", f"{spec.width}x{spec.height}", "-r", str(spec.fps),
        "-i", "pipe:0",
        "-an", "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
        "-profile:v", "baseline", "-pix_fmt", "yuv420p",
        "-g", str(spec.fps), "-keyint_min", str(spec.fps), "-sc_threshold", "0",
        "-b:v", "1200k",
        "-bsf:v", "h264_mp4toannexb",
        "-f", "h264", out_path,
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for frame in render_frames(spec):
            proc.stdin.write(frame.tobytes())
    finally:
        proc.stdin.close()
        rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"ffmpeg failed with rc={rc}")
    return out_path


DEFAULT_SCENES = [
    SceneSpec("perimeter_day",    "perimeter",  1280, 720, 15, 20, night=False),
    SceneSpec("perimeter_day_sub", "perimeter",  704, 396, 15, 20, night=False),
    SceneSpec("perimeter_night",  "perimeter",  1280, 720, 15, 20, night=True),
    SceneSpec("gate_day",         "chokepoint", 1280, 720, 15, 20, night=False),
    SceneSpec("gate_day_sub",     "chokepoint",  704, 396, 15, 20, night=False),
]


def build_all(media_dir: str = "media") -> dict:
    out = {}
    for spec in DEFAULT_SCENES:
        path = os.path.join(media_dir, f"{spec.name}.h264")
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            encode(spec, path)
        out[spec.name] = (path, spec)
    return out


if __name__ == "__main__":
    for name, (path, spec) in build_all().items():
        print(f"{name:22s} {path}  {os.path.getsize(path)/1024:8.1f} KiB  "
              f"{spec.width}x{spec.height}@{spec.fps}")
