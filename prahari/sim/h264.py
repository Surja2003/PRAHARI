"""H.264 Annex-B parsing and RTP packetisation.

Used by the DVR simulator to serve a real, decodable H.264 stream over
RTSP/RTP so that the Camera Abstraction Layer, ffmpeg, VLC and OpenCV all
see exactly what they would see from a physical DVR.

Nothing here is simulator-specific in a way that matters: the packetiser
implements RFC 6184 (single NAL unit packets and FU-A fragmentation), which
is what every real camera emits.
"""
from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from typing import Iterator, List

RTP_PAYLOAD_TYPE = 96
CLOCK_HZ = 90000
MAX_PAYLOAD = 1400  # conservative, keeps us under a 1500-byte MTU


# --------------------------------------------------------------------------
# Annex-B parsing
# --------------------------------------------------------------------------

def split_nalus(data: bytes) -> Iterator[bytes]:
    """Yield NAL units from an Annex-B byte stream (start codes removed)."""
    i, n = 0, len(data)
    # find first start code
    start = -1
    while i < n - 3:
        if data[i] == 0 and data[i + 1] == 0:
            if data[i + 2] == 1:
                start = i + 3
                i += 3
                break
            if i < n - 4 and data[i + 2] == 0 and data[i + 3] == 1:
                start = i + 4
                i += 4
                break
        i += 1
    if start < 0:
        return

    while i < n:
        if data[i] == 0 and i + 2 < n and data[i + 1] == 0:
            if data[i + 2] == 1:
                nal = data[start:i]
                if nal:
                    yield nal
                i += 3
                start = i
                continue
            if i + 3 < n and data[i + 2] == 0 and data[i + 3] == 1:
                nal = data[start:i]
                if nal:
                    yield nal
                i += 4
                start = i
                continue
        i += 1
    tail = data[start:]
    if tail:
        yield tail


def nal_type(nalu: bytes) -> int:
    return nalu[0] & 0x1F if nalu else 0


VCL_TYPES = {1, 2, 3, 4, 5}


def _ue(data: bytes, bitpos: int = 0):
    """Decode one unsigned exp-Golomb value. Returns (value, next_bitpos)."""
    lead = 0
    while True:
        byte = bitpos >> 3
        if byte >= len(data):
            return 0, bitpos
        bit = (data[byte] >> (7 - (bitpos & 7))) & 1
        bitpos += 1
        if bit:
            break
        lead += 1
        if lead > 32:
            return 0, bitpos
    value = 1
    for _ in range(lead):
        byte = bitpos >> 3
        if byte >= len(data):
            return 0, bitpos
        bit = (data[byte] >> (7 - (bitpos & 7))) & 1
        bitpos += 1
        value = (value << 1) | bit
    return value - 1, bitpos


def starts_picture(nalu: bytes) -> bool:
    """True when this VCL NAL is the first slice of a coded picture.

    Encoders emit several slices per frame whenever sliced threading is on
    (x264 does it by default under -tune zerolatency), so 'one VCL NAL ==
    one frame' is wrong on plenty of real camera streams. The slice header
    opens with first_mb_in_slice; only the slice that starts at macroblock
    zero begins a new picture.
    """
    if nal_type(nalu) not in VCL_TYPES or len(nalu) < 2:
        return False
    first_mb, _ = _ue(nalu[1:], 0)
    return first_mb == 0


@dataclass
class AccessUnit:
    """One coded picture: its VCL NAL plus any parameter sets ahead of it."""
    nalus: List[bytes] = field(default_factory=list)
    keyframe: bool = False


@dataclass
class H264Stream:
    """A parsed Annex-B elementary stream, ready to packetise and loop."""
    sps: bytes
    pps: bytes
    units: List[AccessUnit]
    fps: float
    width: int
    height: int

    @property
    def sprop(self) -> str:
        return "{},{}".format(
            base64.b64encode(self.sps).decode(),
            base64.b64encode(self.pps).decode(),
        )

    @property
    def profile_level_id(self) -> str:
        # profile_idc, constraint flags, level_idc — bytes 1..3 of the SPS
        return self.sps[1:4].hex()

    def sdp(self, control: str = "trackID=0") -> str:
        return "\r\n".join([
            "m=video 0 RTP/AVP {}".format(RTP_PAYLOAD_TYPE),
            "a=rtpmap:{} H264/{}".format(RTP_PAYLOAD_TYPE, CLOCK_HZ),
            "a=fmtp:{} packetization-mode=1;profile-level-id={};"
            "sprop-parameter-sets={}".format(
                RTP_PAYLOAD_TYPE, self.profile_level_id, self.sprop),
            "a=control:{}".format(control),
            "a=framerate:{:.2f}".format(self.fps),
            "a=x-dimensions:{},{}".format(self.width, self.height),
        ]) + "\r\n"


def parse_annexb(data: bytes, fps: float, width: int, height: int) -> H264Stream:
    """Group an Annex-B stream into access units and pull out SPS/PPS."""
    sps = pps = b""
    units: List[AccessUnit] = []
    prefix: List[bytes] = []      # non-VCL NALs waiting for their picture
    current: List[bytes] = []     # slices of the picture being assembled
    keyframe = False

    def flush():
        nonlocal current, keyframe
        if current:
            units.append(AccessUnit(nalus=list(current), keyframe=keyframe))
        current = []
        keyframe = False

    for nalu in split_nalus(data):
        t = nal_type(nalu)
        if t == 9:  # access unit delimiter -- we rebuild boundaries ourselves
            continue
        if t == 7:
            sps = nalu
        elif t == 8:
            pps = nalu

        if t in VCL_TYPES:
            if starts_picture(nalu) and current:
                flush()
            if prefix:
                current.extend(prefix)
                prefix = []
            current.append(nalu)
            if t == 5:
                keyframe = True
        else:
            if current:      # non-VCL after a picture belongs to the next one
                flush()
            prefix.append(nalu)
    flush()

    if not sps or not pps:
        raise ValueError("stream carries no SPS/PPS; encode with -bsf:v h264_mp4toannexb")
    if not units:
        raise ValueError("stream carries no coded pictures")
    return H264Stream(sps=sps, pps=pps, units=units, fps=fps,
                      width=width, height=height)


# --------------------------------------------------------------------------
# RTP packetisation (RFC 6184)
# --------------------------------------------------------------------------

class RtpPacketiser:
    def __init__(self, ssrc: int, payload_type: int = RTP_PAYLOAD_TYPE):
        self.ssrc = ssrc & 0xFFFFFFFF
        self.pt = payload_type
        self.seq = 0

    def _header(self, timestamp: int, marker: bool) -> bytes:
        self.seq = (self.seq + 1) & 0xFFFF
        b0 = 0x80  # version 2, no padding, no extension, CSRC count 0
        b1 = (0x80 if marker else 0x00) | self.pt
        return struct.pack("!BBHII", b0, b1, self.seq, timestamp & 0xFFFFFFFF, self.ssrc)

    def packetise_nalu(self, nalu: bytes, timestamp: int, last: bool) -> List[bytes]:
        """One NAL unit -> one or more RTP packets."""
        if len(nalu) <= MAX_PAYLOAD:
            return [self._header(timestamp, last) + nalu]

        # FU-A fragmentation
        indicator = (nalu[0] & 0xE0) | 28          # F|NRI from original, type 28
        original_type = nalu[0] & 0x1F
        body = nalu[1:]
        packets: List[bytes] = []
        offset = 0
        chunk = MAX_PAYLOAD - 2
        while offset < len(body):
            piece = body[offset:offset + chunk]
            first = offset == 0
            offset += chunk
            end = offset >= len(body)
            fu_header = (0x80 if first else 0) | (0x40 if end else 0) | original_type
            marker = last and end
            packets.append(
                self._header(timestamp, marker)
                + bytes([indicator, fu_header])
                + piece
            )
        return packets

    def packetise_au(self, au: AccessUnit, timestamp: int) -> List[bytes]:
        packets: List[bytes] = []
        for idx, nalu in enumerate(au.nalus):
            last = idx == len(au.nalus) - 1
            packets.extend(self.packetise_nalu(nalu, timestamp, last))
        return packets


def interleave(channel: int, packet: bytes) -> bytes:
    """Wrap an RTP packet for RTP-over-RTSP-TCP transport (RFC 2326 §10.12)."""
    return b"$" + bytes([channel]) + struct.pack("!H", len(packet)) + packet
