"""What a camera can honestly support, derived from what it can resolve.

Capability gating is the core honesty mechanism in Prahari: a camera
watching 400 m of open ground cannot read a number plate or match a face,
and no model quality changes that. Rather than assert thresholds, derive
them from anthropometry and the Indian plate standard so every number can
be defended in a review.

Reference dimensions
    adult stature                    1700 mm
    interpupillary distance (IPD)      63 mm     -> 0.037 of stature
    face width (bizygomatic)          150 mm     -> 0.088 of stature
    face height (menton-crinion)      230 mm     -> 0.135 of stature
    car number plate (IND, 4-wheel)   500 mm     -> 0.294 of stature
    car body width                   1800 mm

Recognition thresholds are the conservative end of what the literature and
vendor guidance report:
    face DETECTION       >= 16 px face width      (SCRFD/RetinaFace class)
    face MATCHING        >= 40 px IPD             (ArcFace/AdaFace class)
    plate OCR            >= 100 px plate width
    pose estimation      >= 60 px person height
    person detection     >= 20 px person height
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

# --- body / object ratios, relative to adult stature ----------------------
IPD_RATIO = 0.037
FACE_W_RATIO = 0.088
PLATE_RATIO = 0.294          # plate width vs a standing adult's height
PLATE_TO_CAR_WIDTH = 500 / 1800.0

# --- thresholds -----------------------------------------------------------
MIN_PERSON_PX_DETECT = 20
MIN_PERSON_PX_POSE = 60
MIN_FACE_W_PX_DETECT = 16
MIN_IPD_PX_MATCH = 40
MIN_PLATE_W_PX_OCR = 100


class Capability(str, Enum):
    HUMAN_DETECT = "human_detect"          # PS capability 01
    HUMAN_TRACK = "human_track"            # PS capability 01
    VEHICLE_DETECT = "vehicle_detect"      # PS capability 02
    FACE_DETECT = "face_detect"            # PS capability 03
    FACE_MATCH = "face_match"              # PS capability 03 (gated)
    ANPR = "anpr"                          # PS capability 04
    VIRTUAL_FENCE = "virtual_fence"        # PS capability 05
    ACTIVITY = "activity"                  # PS capability 06
    NIGHT_MOVEMENT = "night_movement"      # PS capability 07


class Role(str, Enum):
    UNKNOWN = "unknown"
    PERIMETER = "perimeter"
    APPROACH = "approach"
    CHOKEPOINT = "chokepoint"


@dataclass
class Optics:
    """Observed scale statistics for one camera view."""
    median_person_px: float = 0.0
    p90_person_px: float = 0.0
    median_vehicle_w_px: float = 0.0
    p90_vehicle_w_px: float = 0.0
    samples_person: int = 0
    samples_vehicle: int = 0
    frame_width: int = 0
    frame_height: int = 0

    # -- derived -----------------------------------------------------------
    @property
    def face_width_px(self) -> float:
        return self.p90_person_px * FACE_W_RATIO

    @property
    def ipd_px(self) -> float:
        return self.p90_person_px * IPD_RATIO

    @property
    def plate_width_px(self) -> float:
        """Best available estimate of plate width in this view."""
        if self.p90_vehicle_w_px:
            return self.p90_vehicle_w_px * PLATE_TO_CAR_WIDTH
        return self.p90_person_px * PLATE_RATIO

    def as_dict(self) -> dict:
        return {
            "median_person_px": round(self.median_person_px, 1),
            "p90_person_px": round(self.p90_person_px, 1),
            "median_vehicle_w_px": round(self.median_vehicle_w_px, 1),
            "p90_vehicle_w_px": round(self.p90_vehicle_w_px, 1),
            "face_width_px": round(self.face_width_px, 1),
            "ipd_px": round(self.ipd_px, 1),
            "plate_width_px": round(self.plate_width_px, 1),
            "samples_person": self.samples_person,
            "samples_vehicle": self.samples_vehicle,
        }


@dataclass
class CapabilityVerdict:
    capability: Capability
    enabled: bool
    reason: str
    have: float = 0.0
    need: float = 0.0
    unit: str = "px"

    def as_dict(self) -> dict:
        return {"capability": self.capability.value, "enabled": self.enabled,
                "reason": self.reason, "have": round(self.have, 1),
                "need": self.need, "unit": self.unit}


def classify_role(optics: Optics) -> Role:
    """Role follows from the median observed person height, nothing else."""
    m = optics.median_person_px
    if optics.samples_person < 5 and optics.samples_vehicle < 5:
        return Role.UNKNOWN
    if m >= 150:
        return Role.CHOKEPOINT
    if m >= 60:
        return Role.APPROACH
    return Role.PERIMETER


def assess(optics: Optics) -> List[CapabilityVerdict]:
    """Decide, and explain, which capabilities this view can support."""
    v: List[CapabilityVerdict] = []
    person = optics.p90_person_px
    med = optics.median_person_px

    ok = med >= MIN_PERSON_PX_DETECT
    v.append(CapabilityVerdict(
        Capability.HUMAN_DETECT, ok,
        "people resolve at {:.0f} px".format(med) if ok else
        "people only {:.0f} px tall, need {}".format(med, MIN_PERSON_PX_DETECT),
        med, MIN_PERSON_PX_DETECT))
    v.append(CapabilityVerdict(
        Capability.HUMAN_TRACK, ok,
        "tracking follows detection", med, MIN_PERSON_PX_DETECT))
    v.append(CapabilityVerdict(
        Capability.VIRTUAL_FENCE, ok,
        "rules evaluate on tracked objects", med, MIN_PERSON_PX_DETECT))
    v.append(CapabilityVerdict(
        Capability.NIGHT_MOVEMENT, True,
        "motion gate needs no minimum object size", med, 0))
    v.append(CapabilityVerdict(
        Capability.VEHICLE_DETECT, optics.median_vehicle_w_px >= 32
        or optics.samples_vehicle == 0,
        "vehicles resolve at {:.0f} px wide".format(optics.median_vehicle_w_px),
        optics.median_vehicle_w_px, 32))

    pose_ok = med >= MIN_PERSON_PX_POSE
    v.append(CapabilityVerdict(
        Capability.ACTIVITY, pose_ok,
        "skeletons need {} px of person".format(MIN_PERSON_PX_POSE)
        if not pose_ok else "pose estimation viable",
        med, MIN_PERSON_PX_POSE))

    fw = optics.face_width_px
    face_ok = fw >= MIN_FACE_W_PX_DETECT
    v.append(CapabilityVerdict(
        Capability.FACE_DETECT, face_ok,
        "faces about {:.0f} px wide here, need {}".format(fw, MIN_FACE_W_PX_DETECT),
        fw, MIN_FACE_W_PX_DETECT))

    ipd = optics.ipd_px
    match_ok = ipd >= MIN_IPD_PX_MATCH
    v.append(CapabilityVerdict(
        Capability.FACE_MATCH, match_ok,
        "eye spacing about {:.1f} px, matching needs {}".format(
            ipd, MIN_IPD_PX_MATCH),
        ipd, MIN_IPD_PX_MATCH))

    pw = optics.plate_width_px
    anpr_ok = pw >= MIN_PLATE_W_PX_OCR
    v.append(CapabilityVerdict(
        Capability.ANPR, anpr_ok,
        "plates about {:.0f} px wide here, OCR needs {}".format(
            pw, MIN_PLATE_W_PX_OCR),
        pw, MIN_PLATE_W_PX_OCR))
    return v


def enabled_set(optics: Optics) -> Dict[str, bool]:
    return {x.capability.value: x.enabled for x in assess(optics)}


def required_person_px(capability: Capability) -> Optional[float]:
    """Inverse view: how tall must a person be for this to become possible."""
    return {
        Capability.HUMAN_DETECT: MIN_PERSON_PX_DETECT,
        Capability.ACTIVITY: MIN_PERSON_PX_POSE,
        Capability.FACE_DETECT: MIN_FACE_W_PX_DETECT / FACE_W_RATIO,
        Capability.FACE_MATCH: MIN_IPD_PX_MATCH / IPD_RATIO,
        Capability.ANPR: MIN_PLATE_W_PX_OCR / PLATE_RATIO,
    }.get(capability)
