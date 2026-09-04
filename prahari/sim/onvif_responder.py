"""ONVIF and HTTP surfaces for the simulated DVRs.

Three things, all of which exist so that rungs 1-5 of the discovery ladder
have something real to talk to:

  WS-Discovery (UDP 3702)  device announces itself to a Probe
  ONVIF device service     GetDeviceInformation / GetProfiles / GetStreamUri
  HTTP banner (TCP 80)     a Server: header to fingerprint, and a login page

Crucially, ONVIF can be switched OFF per device -- which is the default
state of a great many shipped DVRs, and the whole reason the fallback rungs
of the ladder exist. The demo has one device with it on and two with it off.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from .rtsp_server import DvrDevice

log = logging.getLogger("prahari.sim.onvif")

SOAP_ENV = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<s:Body>{body}</s:Body></s:Envelope>'
)


def _canonical_url(dev: DvrDevice, ch: int, which: str) -> str:
    """The URL this brand would really hand back from GetStreamUri."""
    d = dev.brand
    if d == "hikvision":
        return f"rtsp://{dev.ip}:{dev.port}/Streaming/Channels/{ch}{'01' if which=='main' else '02'}"
    if d in ("dahua", "cpplus"):
        return (f"rtsp://{dev.ip}:{dev.port}/cam/realmonitor?"
                f"channel={ch}&subtype={0 if which=='main' else 1}")
    if d == "uniview":
        return f"rtsp://{dev.ip}:{dev.port}/unicast/c{ch}/s{0 if which=='main' else 1}/live"
    if d == "hanwha":
        return f"rtsp://{dev.ip}:{dev.port}/LiveChannel/{ch-1}/media.smp"
    if d == "axis":
        return f"rtsp://{dev.ip}:{dev.port}/axis-media/media.amp?camera={ch}"
    if d == "reolink":
        return f"rtsp://{dev.ip}:{dev.port}/h264Preview_{ch:02d}_{'main' if which=='main' else 'sub'}"
    if d == "bosch":
        return f"rtsp://{dev.ip}:{dev.port}/?inst={1 if which=='main' else 2}"
    return f"rtsp://{dev.ip}:{dev.port}/live/ch{ch}"


# --------------------------------------------------------------------------
# ONVIF SOAP over HTTP
# --------------------------------------------------------------------------

class OnvifService:
    """Handles the three ONVIF calls the discovery ladder actually uses."""

    def __init__(self, dev: DvrDevice):
        self.dev = dev
        self.uuid = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, dev.ip))

    def handle(self, body: str) -> Optional[str]:
        d = self.dev.dialect
        if "GetDeviceInformation" in body:
            return SOAP_ENV.format(body=(
                "<tds:GetDeviceInformationResponse>"
                f"<tds:Manufacturer>{d.manufacturer}</tds:Manufacturer>"
                f"<tds:Model>{d.model}</tds:Model>"
                f"<tds:FirmwareVersion>{d.firmware}</tds:FirmwareVersion>"
                f"<tds:SerialNumber>{self.dev.serial}</tds:SerialNumber>"
                f"<tds:HardwareId>{d.model}</tds:HardwareId>"
                "</tds:GetDeviceInformationResponse>"))

        if "GetProfiles" in body:
            parts = []
            for ch in sorted(self.dev.channels):
                for which in ("main", "sub"):
                    st = self.dev.channels[ch].stream(which)
                    token = f"Profile_{ch}_{which}"
                    parts.append(
                        f'<trt:Profiles token="{token}" fixed="true">'
                        f"<tt:Name>{self.dev.channels[ch].name} {which}</tt:Name>"
                        "<tt:VideoEncoderConfiguration>"
                        "<tt:Encoding>H264</tt:Encoding>"
                        f"<tt:Resolution><tt:Width>{st.width}</tt:Width>"
                        f"<tt:Height>{st.height}</tt:Height></tt:Resolution>"
                        f"<tt:RateControl><tt:FrameRateLimit>{int(st.fps)}"
                        "</tt:FrameRateLimit></tt:RateControl>"
                        "</tt:VideoEncoderConfiguration>"
                        "</trt:Profiles>")
            return SOAP_ENV.format(
                body="<trt:GetProfilesResponse>" + "".join(parts)
                     + "</trt:GetProfilesResponse>")

        if "GetStreamUri" in body:
            token = ""
            if "ProfileToken" in body:
                seg = body.split("ProfileToken")[1]
                token = seg.split(">")[1].split("<")[0].strip()
            ch, which = 1, "main"
            if token.startswith("Profile_"):
                try:
                    _, c, w = token.split("_", 2)
                    ch, which = int(c), w
                except Exception:
                    pass
            uri = _canonical_url(self.dev, ch, which)
            return SOAP_ENV.format(body=(
                "<trt:GetStreamUriResponse><trt:MediaUri>"
                f"<tt:Uri>{uri}</tt:Uri>"
                "<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>"
                "<tt:Timeout>PT60S</tt:Timeout>"
                "</trt:MediaUri></trt:GetStreamUriResponse>"))

        if "GetCapabilities" in body:
            return SOAP_ENV.format(body=(
                "<tds:GetCapabilitiesResponse><tds:Capabilities>"
                f"<tt:Media><tt:XAddr>http://{self.dev.ip}:{self.dev.onvif_port}"
                "/onvif/media_service"
                "</tt:XAddr></tt:Media>"
                "</tds:Capabilities></tds:GetCapabilitiesResponse>"))
        return None


# --------------------------------------------------------------------------
# tiny HTTP server (banner + ONVIF endpoint)
# --------------------------------------------------------------------------

class HttpService:
    def __init__(self, dev: DvrDevice, port: int, onvif: bool):
        self.dev = dev
        self.port = port
        self.onvif = OnvifService(dev) if onvif else None
        self.server = None

    async def start(self):
        try:
            self.server = await asyncio.start_server(
                self._client, self.dev.ip, self.port)
        except OSError as exc:
            log.warning("HTTP %s:%d unavailable (%s)", self.dev.ip, self.port, exc)
        return self

    async def _client(self, reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line:
                return
            method, path, *_ = line.decode("latin1").split()
            headers = {}
            while True:
                hl = await reader.readline()
                if not hl or hl in (b"\r\n", b"\n"):
                    break
                k, _, v = hl.decode("latin1").partition(":")
                headers[k.strip().lower()] = v.strip()
            body = ""
            n = int(headers.get("content-length", 0) or 0)
            if n:
                body = (await reader.readexactly(n)).decode("utf-8", "replace")

            if self.onvif and method == "POST" and "onvif" in path.lower():
                resp = self.onvif.handle(body)
                if resp:
                    await self._respond(writer, 200, resp,
                                        "application/soap+xml; charset=utf-8")
                else:
                    await self._respond(writer, 400, "<fault/>",
                                        "application/soap+xml")
                return

            page = (f"<html><head><title>{self.dev.dialect.label} "
                    f"{self.dev.dialect.model}</title></head>"
                    f"<body><h1>{self.dev.dialect.manufacturer}</h1>"
                    f"<p>Model {self.dev.dialect.model} &middot; "
                    f"firmware {self.dev.dialect.firmware}</p>"
                    "<form><input name=username><input name=password "
                    "type=password><button>Login</button></form>"
                    "</body></html>")
            await self._respond(writer, 200, page, "text/html")
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionResetError, ValueError):
            pass
        except Exception:
            log.exception("http error")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _respond(self, writer, code: int, body: str, ctype: str):
        raw = body.encode()
        head = (f"HTTP/1.1 {code} OK\r\n"
                f"Server: {self.dev.dialect.server_header}\r\n"
                f"Content-Type: {ctype}\r\n"
                f"Content-Length: {len(raw)}\r\n"
                "Connection: close\r\n\r\n").encode()
        writer.write(head + raw)
        await writer.drain()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


# --------------------------------------------------------------------------
# WS-Discovery
# --------------------------------------------------------------------------

PROBE_MATCH = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    "<s:Header>"
    "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>"
    "<a:MessageID>urn:uuid:{msg}</a:MessageID>"
    "<a:RelatesTo>{relates}</a:RelatesTo>"
    "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
    "</s:Header><s:Body><d:ProbeMatches><d:ProbeMatch>"
    "<a:EndpointReference><a:Address>{uuid}</a:Address></a:EndpointReference>"
    "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
    "<d:Scopes>onvif://www.onvif.org/name/{name} "
    "onvif://www.onvif.org/hardware/{model} "
    "onvif://www.onvif.org/Profile/Streaming</d:Scopes>"
    "<d:XAddrs>http://{ip}:{onvif_port}/onvif/device_service</d:XAddrs>"
    "<d:MetadataVersion>1</d:MetadataVersion>"
    "</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
)


class WsDiscoveryResponder(asyncio.DatagramProtocol):
    def __init__(self, dev: DvrDevice):
        self.dev = dev
        self.uuid = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, dev.ip))
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            return
        if "Probe" not in text:
            return
        relates = ""
        if "MessageID" in text:
            try:
                relates = text.split("MessageID")[1].split(">")[1].split("<")[0]
            except Exception:
                pass
        d = self.dev.dialect
        reply = PROBE_MATCH.format(
            msg=uuid.uuid4(), relates=relates, uuid=self.uuid,
            name=d.manufacturer.replace(" ", "_"),
            model=d.model, ip=self.dev.ip,
            onvif_port=self.dev.onvif_port)
        try:
            self.transport.sendto(reply.encode(), addr)
        except Exception:
            pass

    @classmethod
    async def start(cls, dev: DvrDevice):
        loop = asyncio.get_running_loop()
        try:
            transport, proto = await loop.create_datagram_endpoint(
                lambda: cls(dev), local_addr=(dev.ip, 3702),
                allow_broadcast=True)
            return transport, proto
        except OSError as exc:
            log.warning("WS-Discovery %s:3702 unavailable (%s)", dev.ip, exc)
            return None, None
