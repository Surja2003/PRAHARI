"""Per-brand RTSP dialects for the DVR simulator.

Each dialect answers one question: given the request path a client asked
for, which channel and which stream (main/sub) did it mean -- or is it a
404? Getting these right is the entire point of the simulator, because it
is what the Camera Abstraction Layer's discovery ladder is tested against.

Path formats cross-checked against vendor documentation and the URL library
in config/brands.yaml.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Tuple
from urllib.parse import parse_qs, urlparse

# (channel [1-based], stream) where stream is "main" or "sub"
Resolved = Optional[Tuple[int, str]]


def _q(path: str, key: str) -> Optional[str]:
    vals = parse_qs(urlparse(path).query).get(key)
    return vals[0] if vals else None


# --------------------------------------------------------------------------
# resolvers
# --------------------------------------------------------------------------

def hikvision(path: str) -> Resolved:
    # /Streaming/Channels/101  ->  channel 1, main    (last 2 digits = stream)
    # /Streaming/Channels/402  ->  channel 4, sub
    m = re.match(r"^/Streaming/Channels/(\d+)/?$", urlparse(path).path, re.I)
    if m:
        code = m.group(1)
        if len(code) < 3:
            return None
        ch, stream = int(code[:-2]), code[-2:]
        if stream == "01":
            return ch, "main"
        if stream == "02":
            return ch, "sub"
        return None
    # older firmware
    m = re.match(r"^/h264/ch(\d+)/(main|sub)/av_stream$", urlparse(path).path, re.I)
    if m:
        return int(m.group(1)), m.group(2).lower()
    return None


def dahua(path: str) -> Resolved:
    # /cam/realmonitor?channel=1&subtype=0
    if not re.match(r"^/cam/realmonitor$", urlparse(path).path, re.I):
        return None
    ch = _q(path, "channel")
    st = _q(path, "subtype")
    if ch is None or st is None:
        return None
    try:
        ch_i = int(ch)
    except ValueError:
        return None
    if st == "0":
        return ch_i, "main"
    if st == "1":
        return ch_i, "sub"
    return None


def uniview(path: str) -> Resolved:
    p = urlparse(path).path
    m = re.match(r"^/unicast/c(\d+)/s(\d+)/live$", p, re.I)
    if m:
        ch, s = int(m.group(1)), m.group(2)
        return (ch, "main") if s == "0" else ((ch, "sub") if s == "1" else None)
    m = re.match(r"^/media/video(\d+)$", p, re.I)
    if m:
        return int(m.group(1)), "main"
    return None


def hanwha(path: str) -> Resolved:
    p = urlparse(path).path
    m = re.match(r"^/LiveChannel/(\d+)/media\.smp$", p, re.I)
    if m:
        return int(m.group(1)) + 1, "main"        # 0-based on the wire
    m = re.match(r"^/profile(\d+)/media\.smp$", p, re.I)
    if m:
        return 1, "main" if m.group(1) == "1" else "sub"
    return None


def axis(path: str) -> Resolved:
    if not re.match(r"^/axis-media/media\.amp$", urlparse(path).path, re.I):
        return None
    cam = _q(path, "camera")
    ch = int(cam) if cam and cam.isdigit() else 1
    return ch, "sub" if _q(path, "resolution") else "main"


def reolink(path: str) -> Resolved:
    m = re.match(r"^/h264Preview_(\d+)_(main|sub)$", urlparse(path).path, re.I)
    return (int(m.group(1)), m.group(2).lower()) if m else None


def bosch(path: str) -> Resolved:
    p = urlparse(path)
    if p.path not in ("/", "/rtsp_tunnel"):
        return None
    inst = _q(path, "inst")
    if inst == "1":
        return 1, "main"
    if inst == "2":
        return 1, "sub"
    return None


def generic(path: str) -> Resolved:
    p = urlparse(path).path
    for pat, ch_group in (
        (r"^/live$", None),
        (r"^/live/ch(\d+)$", 1),
        (r"^/stream(\d+)$", 1),
        (r"^/video(\d+)$", 1),
        (r"^/ch(\d+)/0$", 1),
        (r"^/onvif(\d+)$", 1),
        (r"^/11$", None),
    ):
        m = re.match(pat, p, re.I)
        if m:
            return (int(m.group(ch_group)) if ch_group else 1), "main"
    return None


@dataclass(frozen=True)
class Dialect:
    name: str
    label: str
    server_header: str
    auth: str                 # "digest" | "basic" | "none"
    realm: str
    resolve: Callable[[str], Resolved]
    manufacturer: str
    model: str
    firmware: str
    oui: str
    # Ports the device also listens on, purely so port fingerprinting
    # (discovery ladder rung 4) has something true to find.
    extra_ports: tuple = ()


DIALECTS = {
    "hikvision": Dialect(
        "hikvision", "Hikvision", "Hikvision-Webs", "digest", "IP Camera(C1234)",
        hikvision, "Hikvision", "DS-7208HQHI-K1", "V4.30.005", "44:19:b6",
        extra_ports=(80, 8000)),
    "dahua": Dialect(
        "dahua", "Dahua", "Rtsp Server", "digest", "Login to 3ff4ba1c1c1f9f4b",
        dahua, "Dahua", "XVR5108HS-I3", "V4.001.0000000.2", "3c:ef:8c",
        extra_ports=(80, 37777)),
    "cpplus": Dialect(
        "cpplus", "CP Plus", "Rtsp Server", "digest", "Login to 3ff4ba1c1c1f9f4b",
        dahua, "CP Plus", "CP-UVR-0801E1-CS", "V4.000.0000001.5", "8c:e7:48",
        extra_ports=(80, 37777)),
    "uniview": Dialect(
        "uniview", "Uniview", "UNV-RTSP/1.0", "basic", "uniview",
        uniview, "Uniview", "NVR301-08S3", "UNV-B3121.5", "48:ea:63",
        extra_ports=(80, 8000)),
    "hanwha": Dialect(
        "hanwha", "Hanwha", "Hanwha", "digest", "iPolis",
        hanwha, "Hanwha Techwin", "HRX-821", "1.41.03", "00:16:6c",
        extra_ports=(80,)),
    "axis": Dialect(
        "axis", "Axis", "GStreamer RTSP server", "digest", "AXIS_ACCC8E",
        axis, "Axis Communications", "P1435-LE", "10.12.182", "ac:cc:8e",
        extra_ports=(80,)),
    "reolink": Dialect(
        "reolink", "Reolink", "Rtsp Server", "basic", "reolink",
        reolink, "Reolink", "RLN8-410", "v3.1.0.156", "ec:71:db",
        extra_ports=(80,)),
    "bosch": Dialect(
        "bosch", "Bosch", "Bosch VIP", "digest", "VIP",
        bosch, "Bosch", "DIP-7180-00N", "8.10.0155", "00:07:5f",
        extra_ports=(80, 1756)),
    "generic": Dialect(
        "generic", "Generic RTSP", "RTSP Server", "basic", "rtsp",
        generic, "Unknown", "IPC", "1.0.0", "00:00:00"),
}
