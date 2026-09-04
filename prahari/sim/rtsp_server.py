"""A minimal but genuine RTSP 1.0 server that impersonates field DVRs.

Speaks enough of RFC 2326 that ffmpeg, VLC, OpenCV and the Camera
Abstraction Layer all treat it as a real device:

  OPTIONS / DESCRIBE / SETUP / PLAY / TEARDOWN / GET_PARAMETER
  Basic and Digest authentication, per brand
  RTP/AVP/TCP interleaved delivery of real H.264
  Brand-correct paths -- and brand-correct 404s for the wrong ones

The 404s matter as much as the 200s: the discovery ladder is only proved
by a device that refuses the templates that do not belong to it.

Link impairment (loss, added delay, bandwidth ceiling, hard outage) is
applied in the sending loop, which is what lets the demo degrade a link
live in front of an audience.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .dialects import DIALECTS, Dialect
from .h264 import H264Stream, RtpPacketiser, interleave, parse_annexb

log = logging.getLogger("prahari.sim.rtsp")

RTSP_OK = "200 OK"
RTSP_UNAUTH = "401 Unauthorized"
RTSP_NOTFOUND = "404 Not Found"
RTSP_BADREQ = "400 Bad Request"
RTSP_UNSUPP = "461 Unsupported Transport"
RTSP_SESSNF = "454 Session Not Found"


# --------------------------------------------------------------------------
# link impairment
# --------------------------------------------------------------------------

@dataclass
class LinkProfile:
    """Shared, mutable link state. The demo slider writes to this."""
    name: str = "fibre"
    kbps: int = 0          # 0 = unlimited
    loss: float = 0.0      # 0..1 packet loss probability
    delay_ms: int = 0
    up: bool = True

    def snapshot(self) -> dict:
        return {"name": self.name, "kbps": self.kbps, "loss": self.loss,
                "delay_ms": self.delay_ms, "up": self.up}


PRESETS: Dict[str, LinkProfile] = {
    "fibre":     LinkProfile("fibre", 0, 0.000, 1, True),
    "p2p_5ghz":  LinkProfile("p2p_5ghz", 40_000, 0.002, 8, True),
    "wifi":      LinkProfile("wifi", 20_000, 0.010, 20, True),
    "lte":       LinkProfile("lte", 4_000, 0.030, 90, True),
    "vsat":      LinkProfile("vsat", 1_200, 0.060, 600, True),
    "down":      LinkProfile("down", 0, 1.0, 0, False),
}


# --------------------------------------------------------------------------
# media
# --------------------------------------------------------------------------

@dataclass
class Channel:
    number: int
    name: str
    main: H264Stream
    sub: H264Stream
    role_hint: str = "perimeter"     # what the footage actually depicts

    def stream(self, which: str) -> H264Stream:
        return self.main if which == "main" else self.sub


_STREAM_CACHE: Dict[Tuple[str, int, int, int], H264Stream] = {}


def load_stream(path: str, fps: int, width: int, height: int) -> H264Stream:
    key = (os.path.abspath(path), fps, width, height)
    if key not in _STREAM_CACHE:
        with open(path, "rb") as fh:
            _STREAM_CACHE[key] = parse_annexb(fh.read(), fps, width, height)
    return _STREAM_CACHE[key]


# --------------------------------------------------------------------------
# device
# --------------------------------------------------------------------------

@dataclass
class DvrDevice:
    ip: str
    brand: str
    channels: Dict[int, Channel]
    username: str = "admin"
    password: str = "admin"
    port: int = 554
    serial: str = "SIM0000000001"
    onvif_enabled: bool = True
    link: LinkProfile = field(default_factory=lambda: LinkProfile())
    # Windows routes only 127.0.0.1 to the loopback interface, so the
    # one-IP-per-DVR layout is Linux-only. In port mode every device shares
    # 127.0.0.1 and is separated by port instead; these carry the auxiliary
    # ports so nothing else has to know which mode is in force.
    http_port: int = 80
    onvif_port: int = 8000
    extra_ports: tuple = ()

    @property
    def key(self) -> str:
        """Stable identity. In port mode the IP alone is not unique."""
        return self.ip if self.port == 554 else f"{self.ip}:{self.port}"

    @property
    def dialect(self) -> Dialect:
        return DIALECTS[self.brand]

    @property
    def mac(self) -> str:
        tail = ":".join(f"{b:02x}" for b in hashlib.md5(
            self.ip.encode()).digest()[:3])
        return f"{self.dialect.oui}:{tail}"

    def describe(self) -> dict:
        d = self.dialect
        return {
            "key": self.key, "ip": self.ip, "port": self.port,
            "brand": self.brand,
            "manufacturer": d.manufacturer, "model": d.model,
            "firmware": d.firmware, "serial": self.serial, "mac": self.mac,
            "channels": len(self.channels), "onvif": self.onvif_enabled,
            "auth": d.auth, "link": self.link.snapshot(),
            "http_port": self.http_port, "onvif_port": self.onvif_port,
        }


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------

@dataclass
class Session:
    sid: str
    channel: Channel
    which: str
    interleaved: Tuple[int, int] = (0, 1)
    task: Optional[asyncio.Task] = None
    playing: bool = False
    packets_sent: int = 0
    packets_dropped: int = 0


class RtspConnection:
    def __init__(self, device: DvrDevice, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, server: "RtspServer"):
        self.dev = device
        self.reader = reader
        self.writer = writer
        self.server = server
        self.sessions: Dict[str, Session] = {}
        self.nonce = secrets.token_hex(16)
        self.write_lock = asyncio.Lock()
        self.peer = writer.get_extra_info("peername")

    # -------------------------------------------------- request parsing
    async def read_request(self):
        line = await self.reader.readline()
        if not line:
            return None
        try:
            text = line.decode("utf-8", "replace").strip()
        except Exception:
            return None
        if not text:
            return await self.read_request()
        parts = text.split()
        if len(parts) < 3:
            return None
        method, uri, version = parts[0], parts[1], parts[2]
        headers: Dict[str, str] = {}
        while True:
            hl = await self.reader.readline()
            if not hl or hl in (b"\r\n", b"\n"):
                break
            try:
                k, _, v = hl.decode("utf-8", "replace").partition(":")
                headers[k.strip().lower()] = v.strip()
            except Exception:
                pass
        n = int(headers.get("content-length", 0) or 0)
        if n:
            await self.reader.readexactly(n)
        return method.upper(), uri, version, headers

    # -------------------------------------------------- responses
    async def send(self, status: str, cseq: str, headers=None, body: str = ""):
        headers = dict(headers or {})
        headers.setdefault("CSeq", cseq)
        headers.setdefault("Server", self.dev.dialect.server_header)
        headers.setdefault("Date", time.strftime(
            "%a, %d %b %Y %H:%M:%S GMT", time.gmtime()))
        if body:
            headers["Content-Length"] = str(len(body.encode()))
        lines = [f"RTSP/1.0 {status}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        payload = ("\r\n".join(lines) + "\r\n\r\n" + body).encode()
        async with self.write_lock:
            self.writer.write(payload)
            await self.writer.drain()

    # -------------------------------------------------- auth
    def _check_auth(self, method: str, uri: str, headers: Dict[str, str]) -> bool:
        d = self.dev.dialect
        if d.auth == "none":
            return True
        hdr = headers.get("authorization", "")
        if not hdr:
            return False
        if d.auth == "basic":
            import base64
            if not hdr.lower().startswith("basic "):
                return False
            try:
                raw = base64.b64decode(hdr.split(None, 1)[1]).decode()
            except Exception:
                return False
            u, _, p = raw.partition(":")
            return u == self.dev.username and p == self.dev.password
        # digest
        if not hdr.lower().startswith("digest "):
            return False
        fields = {}
        for part in hdr[7:].split(","):
            k, _, v = part.strip().partition("=")
            fields[k.strip().lower()] = v.strip().strip('"')
        if fields.get("username") != self.dev.username:
            return False
        ha1 = hashlib.md5(
            f"{self.dev.username}:{d.realm}:{self.dev.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{fields.get('uri', uri)}".encode()).hexdigest()
        expect = hashlib.md5(
            f"{ha1}:{fields.get('nonce','')}:{ha2}".encode()).hexdigest()
        return secrets.compare_digest(expect, fields.get("response", ""))

    async def _challenge(self, cseq: str):
        d = self.dev.dialect
        if d.auth == "basic":
            www = f'Basic realm="{d.realm}"'
        else:
            www = (f'Digest realm="{d.realm}", nonce="{self.nonce}", '
                   f'stale="FALSE"')
        await self.send(RTSP_UNAUTH, cseq, {"WWW-Authenticate": www})

    # -------------------------------------------------- methods
    async def handle(self):
        try:
            while True:
                req = await self.read_request()
                if req is None:
                    break
                method, uri, _version, headers = req
                cseq = headers.get("cseq", "0")
                self.server.stats["requests"] += 1

                if method == "OPTIONS":
                    await self.send(RTSP_OK, cseq, {
                        "Public": "OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, "
                                  "GET_PARAMETER"})
                    continue

                if method in ("DESCRIBE", "SETUP", "PLAY", "TEARDOWN",
                              "GET_PARAMETER"):
                    if not self._check_auth(method, uri, headers):
                        self.server.stats["challenges"] += 1
                        await self._challenge(cseq)
                        continue

                if method == "DESCRIBE":
                    await self._describe(uri, cseq)
                elif method == "SETUP":
                    await self._setup(uri, cseq, headers)
                elif method == "PLAY":
                    await self._play(cseq, headers)
                elif method == "TEARDOWN":
                    await self._teardown(cseq, headers)
                elif method == "GET_PARAMETER":
                    await self.send(RTSP_OK, cseq,
                                    {"Session": headers.get("session", "")})
                else:
                    await self.send("501 Not Implemented", cseq)
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError):
            pass
        except Exception:
            log.exception("rtsp connection error")
        finally:
            for s in self.sessions.values():
                if s.task:
                    s.task.cancel()
            try:
                self.writer.close()
            except Exception:
                pass

    @staticmethod
    def _strip_control(path: str) -> str:
        """Remove the SDP control token clients append for SETUP/PLAY.

        ffmpeg and VLC build the SETUP URI as Content-Base + the media
        level's a=control value, giving '.../Streaming/Channels/101/trackID=0'.
        On Dahua-style URLs the token lands inside the query string
        ('...?channel=2&subtype=1/trackID=0'), so this has to operate on the
        raw string rather than on a parsed path.
        """
        return re.sub(r"/(?:trackID|trackId|track|streamid|stream)=?\d*/?$",
                      "", path)

    def _resolve(self, uri: str):
        path = uri
        if uri.lower().startswith("rtsp://"):
            rest = uri[7:]
            slash = rest.find("/")
            path = rest[slash:] if slash >= 0 else "/"
        path = self._strip_control(path)
        got = self.dev.dialect.resolve(path)
        if not got:
            return None
        ch_no, which = got
        ch = self.dev.channels.get(ch_no)
        return (ch, which) if ch else None

    async def _describe(self, uri: str, cseq: str):
        got = self._resolve(uri)
        if not got:
            self.server.stats["not_found"] += 1
            await self.send(RTSP_NOTFOUND, cseq)
            return
        ch, which = got
        stream = ch.stream(which)
        sdp = ("v=0\r\n"
               "o=- 0 0 IN IP4 {ip}\r\n"
               "s={name}\r\n"
               "c=IN IP4 0.0.0.0\r\n"
               "t=0 0\r\n"
               "a=tool:{tool}\r\n"
               "a=range:npt=0-\r\n").format(
                   ip=self.dev.ip, name=ch.name,
                   tool=self.dev.dialect.server_header) + stream.sdp()
        self.server.stats["described"] += 1
        await self.send(RTSP_OK, cseq, {
            "Content-Type": "application/sdp",
            "Content-Base": uri if uri.endswith("/") else uri + "/",
        }, sdp)

    async def _setup(self, uri: str, cseq: str, headers: Dict[str, str]):
        got = self._resolve(uri)
        if not got:
            await self.send(RTSP_NOTFOUND, cseq)
            return
        ch, which = got
        transport = headers.get("transport", "")
        if "tcp" not in transport.lower():
            # Plenty of field DVRs behave exactly like this, and it is why
            # the CAL prefers TCP anyway.
            await self.send(RTSP_UNSUPP, cseq, {
                "Transport": "RTP/AVP/TCP;unicast;interleaved=0-1"})
            return
        inter = (0, 1)
        for tok in transport.split(";"):
            if tok.strip().lower().startswith("interleaved="):
                try:
                    a, _, b = tok.split("=", 1)[1].partition("-")
                    inter = (int(a), int(b or int(a) + 1))
                except Exception:
                    pass
        sid = secrets.token_hex(4).upper()
        self.sessions[sid] = Session(sid, ch, which, inter)
        await self.send(RTSP_OK, cseq, {
            "Session": f"{sid};timeout=60",
            "Transport": f"RTP/AVP/TCP;unicast;interleaved={inter[0]}-{inter[1]}",
        })

    async def _play(self, cseq: str, headers: Dict[str, str]):
        sid = (headers.get("session", "") or "").split(";")[0].strip()
        sess = self.sessions.get(sid)
        if not sess:
            await self.send(RTSP_SESSNF, cseq)
            return
        await self.send(RTSP_OK, cseq, {
            "Session": f"{sid};timeout=60",
            "Range": "npt=0.000-",
            "RTP-Info": f"url=trackID=0;seq=1;rtptime=0",
        })
        sess.playing = True
        sess.task = asyncio.create_task(self._stream(sess))
        self.server.stats["playing"] += 1

    async def _teardown(self, cseq: str, headers: Dict[str, str]):
        sid = (headers.get("session", "") or "").split(";")[0].strip()
        sess = self.sessions.pop(sid, None)
        if sess and sess.task:
            sess.task.cancel()
        await self.send(RTSP_OK, cseq, {"Session": sid})

    # -------------------------------------------------- streaming
    async def _stream(self, sess: Session):
        stream = sess.channel.stream(sess.which)
        pkt = RtpPacketiser(ssrc=random.getrandbits(32))
        step = int(90000 / stream.fps)
        frame_period = 1.0 / stream.fps
        ts = random.getrandbits(24)
        idx = 0
        next_at = time.monotonic()
        link = self.dev.link

        try:
            while sess.playing:
                if not link.up:
                    # Hard outage: hold the connection open but send nothing,
                    # exactly as a dead backhaul looks from the far end.
                    await asyncio.sleep(0.25)
                    next_at = time.monotonic()
                    continue

                au = stream.units[idx % len(stream.units)]
                idx += 1
                packets = pkt.packetise_au(au, ts)
                ts = (ts + step) & 0xFFFFFFFF

                blob = bytearray()
                for p in packets:
                    if link.loss and random.random() < link.loss:
                        sess.packets_dropped += 1
                        continue
                    blob += interleave(sess.interleaved[0], p)
                    sess.packets_sent += 1

                if link.delay_ms:
                    await asyncio.sleep(link.delay_ms / 1000.0)

                if blob:
                    async with self.write_lock:
                        self.writer.write(bytes(blob))
                        try:
                            await self.writer.drain()
                        except (ConnectionResetError, BrokenPipeError):
                            return

                # pace to real time, plus a bandwidth ceiling if one is set
                wait = frame_period
                if link.kbps:
                    need = (len(blob) * 8) / (link.kbps * 1000.0)
                    wait = max(wait, need)
                next_at += wait
                sleep = next_at - time.monotonic()
                if sleep > 0:
                    await asyncio.sleep(sleep)
                else:
                    next_at = time.monotonic()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("streaming error")


class RtspServer:
    def __init__(self, device: DvrDevice):
        self.dev = device
        self.server: Optional[asyncio.AbstractServer] = None
        self.stats = {"requests": 0, "challenges": 0, "described": 0,
                      "not_found": 0, "playing": 0}

    async def start(self):
        self.server = await asyncio.start_server(
            self._on_client, self.dev.ip, self.dev.port)
        log.info("RTSP %s (%s) listening on %s:%d",
                 self.dev.dialect.label, self.dev.brand, self.dev.ip, self.dev.port)
        return self

    async def _on_client(self, reader, writer):
        await RtspConnection(self.dev, reader, writer, self).handle()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
