"""Low-level probes used by the discovery ladder.

An async RTSP client that speaks just enough to ask "is there a stream at
this URL, and what is it?" -- OPTIONS, DESCRIBE, Basic and Digest auth --
plus TCP port probing, HTTP banner grabbing and offline MAC OUI lookup.

Deliberately dependency-free: this has to run on a border outpost with no
internet and whatever Python the box happens to have.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 2.0
USER_AGENT = "Prahari-CAL/0.1"


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------

@dataclass
class RtspResult:
    url: str
    status: int = 0
    ok: bool = False
    server: str = ""
    sdp: str = ""
    width: int = 0
    height: int = 0
    codec: str = ""
    fps: float = 0.0
    error: str = ""
    auth_scheme: str = ""
    elapsed_ms: int = 0

    @property
    def unauthorized(self) -> bool:
        return self.status == 401

    def as_dict(self) -> dict:
        return {"url": redact(self.url), "status": self.status, "ok": self.ok,
                "server": self.server, "codec": self.codec,
                "width": self.width, "height": self.height, "fps": self.fps,
                "auth": self.auth_scheme, "error": self.error,
                "elapsed_ms": self.elapsed_ms}


def redact(url: str) -> str:
    return re.sub(r"//([^:/@]+):([^@]*)@", r"//\1:****@", url)


# --------------------------------------------------------------------------
# SDP parsing
# --------------------------------------------------------------------------

def parse_sdp(sdp: str) -> Tuple[str, int, int, float]:
    codec, w, h, fps = "", 0, 0, 0.0
    m = re.search(r"a=rtpmap:\d+\s+([A-Za-z0-9\-]+)/", sdp)
    if m:
        codec = m.group(1).upper()
    m = re.search(r"a=x-dimensions:\s*(\d+)\s*,\s*(\d+)", sdp)
    if m:
        w, h = int(m.group(1)), int(m.group(2))
    m = re.search(r"a=framerate:\s*([\d.]+)", sdp)
    if m:
        fps = float(m.group(1))
    if not w:
        # Some devices only advertise dimensions inside the H.264 fmtp line's
        # sprop-parameter-sets; decoding SPS geometry is overkill for a probe,
        # so fall back to a common vendor extension.
        m = re.search(r"a=cliprect:\s*\d+\s*,\s*\d+\s*,\s*(\d+)\s*,\s*(\d+)", sdp)
        if m:
            h, w = int(m.group(1)), int(m.group(2))
    return codec, w, h, fps


# --------------------------------------------------------------------------
# RTSP probe
# --------------------------------------------------------------------------

def _digest_header(user: str, password: str, method: str, uri: str,
                   challenge: str) -> str:
    fields = {}
    for part in re.split(r",(?=\s*\w+=)", challenge):
        k, _, v = part.strip().partition("=")
        fields[k.strip().lower()] = v.strip().strip('"')
    realm = fields.get("realm", "")
    nonce = fields.get("nonce", "")
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}"')


async def _read_response(reader: asyncio.StreamReader) -> Tuple[int, Dict[str, str], str]:
    status_line = await reader.readline()
    if not status_line:
        raise ConnectionError("closed before status line")
    parts = status_line.decode("latin1").split(None, 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers: Dict[str, str] = {}
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        k, _, v = line.decode("latin1").partition(":")
        headers[k.strip().lower()] = v.strip()
    body = ""
    n = int(headers.get("content-length", 0) or 0)
    if n:
        body = (await reader.readexactly(n)).decode("utf-8", "replace")
    return status, headers, body


async def rtsp_describe(url: str, timeout: float = DEFAULT_TIMEOUT) -> RtspResult:
    """OPTIONS + DESCRIBE against one candidate URL, handling auth."""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    res = RtspResult(url=url)
    split = urlsplit(url)
    host, port = split.hostname, split.port or 554
    user = split.username or ""
    password = split.password or ""
    # request URI without credentials, which is what devices expect
    netloc = f"{host}:{port}"
    path = split.path + (("?" + split.query) if split.query else "")
    req_uri = f"rtsp://{netloc}{path or '/'}"

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        cseq = 1

        async def send(method: str, extra: str = "") -> Tuple[int, Dict[str, str], str]:
            nonlocal cseq
            req = (f"{method} {req_uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"
                   f"User-Agent: {USER_AGENT}\r\n{extra}\r\n")
            cseq += 1
            writer.write(req.encode())
            await writer.drain()
            return await asyncio.wait_for(_read_response(reader), timeout)

        status, headers, _ = await send("OPTIONS")
        res.server = headers.get("server", "")

        status, headers, body = await send("DESCRIBE",
                                           "Accept: application/sdp\r\n")
        res.server = res.server or headers.get("server", "")

        if status == 401 and (user or password):
            chal = headers.get("www-authenticate", "")
            res.auth_scheme = "digest" if chal.lower().startswith("digest") else "basic"
            if res.auth_scheme == "digest":
                auth = _digest_header(user, password, "DESCRIBE", req_uri,
                                      chal[7:])
            else:
                token = b64encode(f"{user}:{password}".encode()).decode()
                auth = f"Basic {token}"
            status, headers, body = await send(
                "DESCRIBE", f"Accept: application/sdp\r\nAuthorization: {auth}\r\n")
            res.server = res.server or headers.get("server", "")

        res.status = status
        if status == 200 and "v=0" in body:
            res.ok = True
            res.sdp = body
            res.codec, res.width, res.height, res.fps = parse_sdp(body)
        elif status == 401:
            res.error = "authentication failed"
        elif status == 404:
            res.error = "no such stream on this device"
        elif status:
            res.error = f"RTSP {status}"
    except asyncio.TimeoutError:
        res.error = "timeout"
    except (ConnectionRefusedError, OSError) as exc:
        res.error = f"connect: {exc.__class__.__name__}"
    except Exception as exc:                                # noqa: BLE001
        res.error = f"{exc.__class__.__name__}: {exc}"
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    res.elapsed_ms = int((loop.time() - t0) * 1000)
    return res


async def probe_many(urls: List[str], concurrency: int = 24,
                     timeout: float = DEFAULT_TIMEOUT) -> List[RtspResult]:
    """Probe candidate URLs in parallel. First 200 OK wins, but we collect
    everything so the UI can show what was tried and why each one failed."""
    sem = asyncio.Semaphore(concurrency)

    async def one(u):
        async with sem:
            return await rtsp_describe(u, timeout)

    return list(await asyncio.gather(*(one(u) for u in urls)))


# --------------------------------------------------------------------------
# TCP / HTTP probes
# --------------------------------------------------------------------------

async def tcp_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        writer.close()
        return True
    except Exception:
        return False


async def scan_ports(host: str, ports: List[int],
                     timeout: float = 0.6) -> List[int]:
    results = await asyncio.gather(
        *(tcp_open(host, p, timeout) for p in ports))
    return [p for p, ok in zip(ports, results) if ok]


async def http_banner(host: str, port: int = 80,
                      timeout: float = 1.5) -> Tuple[str, str]:
    """Return (Server header, page title) -- both useful fingerprints."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                     f"User-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n"
                     .encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(8192), timeout)
        text = raw.decode("utf-8", "replace")
        server = ""
        m = re.search(r"^Server:\s*(.+)$", text, re.M | re.I)
        if m:
            server = m.group(1).strip()
        title = ""
        m = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
        if m:
            title = m.group(1).strip()
        return server, title
    except Exception:
        return "", ""
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# MAC / OUI
# --------------------------------------------------------------------------

async def arp_lookup(ip: str) -> str:
    """Read the MAC for an IP from the kernel neighbour table.

    Loopback addresses have no ARP entry, so the simulator's devices come
    back empty here -- which is honest, and the ladder simply moves on.
    """
    try:
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                cols = line.split()
                if cols and cols[0] == ip and len(cols) > 3:
                    mac = cols[3]
                    if mac and mac != "00:00:00:00:00:00":
                        return mac.lower()
    except Exception:
        pass
    return ""


def oui_of(mac: str) -> str:
    return ":".join(mac.lower().split(":")[:3]) if mac else ""
