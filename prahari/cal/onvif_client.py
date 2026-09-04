"""ONVIF client: rungs 1-3 of the discovery ladder.

WS-Discovery to find devices, then GetDeviceInformation for identity and
GetProfiles -> GetStreamUri for the authoritative stream URL. When a device
answers these, no brand guessing is needed at all -- it tells you its own
URLs. The rest of the ladder exists only because so many field devices
ship with ONVIF switched off.

Hand-rolled SOAP rather than onvif-zeep: three calls do not justify a WSDL
stack, and a BOP appliance benefits from having no wheel to install.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .probe import USER_AGENT

WS_DISCOVERY_ADDR = "239.255.255.250"
WS_DISCOVERY_PORT = 3702

PROBE_MSG = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    "<s:Header>"
    "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>"
    "<a:MessageID>urn:uuid:{msg}</a:MessageID>"
    "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
    "</s:Header>"
    "<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>"
    "</s:Body></s:Envelope>"
)

_SOAP = ('<?xml version="1.0" encoding="UTF-8"?>'
         '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
         'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
         'xmlns:trt="http://www.onvif.org/ver10/media/wsdl">'
         "<s:Body>{body}</s:Body></s:Envelope>")


@dataclass
class OnvifDevice:
    ip: str
    xaddr: str = ""
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    scopes: str = ""
    profiles: List[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ip": self.ip, "xaddr": self.xaddr,
                "manufacturer": self.manufacturer, "model": self.model,
                "firmware": self.firmware, "serial": self.serial,
                "profiles": self.profiles}


def _tag(xml: str, name: str) -> str:
    m = re.search(rf"<(?:\w+:)?{name}[^>]*>(.*?)</(?:\w+:)?{name}>", xml, re.S)
    return m.group(1).strip() if m else ""


def _tags(xml: str, name: str) -> List[str]:
    return [m.strip() for m in re.findall(
        rf"<(?:\w+:)?{name}[^>]*>(.*?)</(?:\w+:)?{name}>", xml, re.S)]


# --------------------------------------------------------------------------
# rung 1: WS-Discovery
# --------------------------------------------------------------------------

class _ProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies: List[Tuple[str, str]] = []

    def datagram_received(self, data, addr):
        try:
            self.replies.append((addr[0], data.decode("utf-8", "replace")))
        except Exception:
            pass

    def error_received(self, exc):
        pass


async def ws_discover(targets: Optional[List[str]] = None,
                      timeout: float = 2.0) -> List[OnvifDevice]:
    """Multicast Probe, plus unicast Probes to any explicitly named hosts.

    Multicast is the standard path; the unicast sweep is what makes this
    work across a routed BOP network (and on a loopback test rig) where
    multicast does not propagate.
    """
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        _ProbeProtocol, local_addr=("0.0.0.0", 0), allow_broadcast=True)
    msg = PROBE_MSG.format(msg=uuid.uuid4()).encode()
    try:
        try:
            transport.sendto(msg, (WS_DISCOVERY_ADDR, WS_DISCOVERY_PORT))
        except Exception:
            pass
        for host in targets or []:
            try:
                transport.sendto(msg, (host, WS_DISCOVERY_PORT))
            except Exception:
                pass
        await asyncio.sleep(timeout)
    finally:
        transport.close()

    devices: Dict[str, OnvifDevice] = {}
    for ip, xml in proto.replies:
        if "ProbeMatch" not in xml:
            continue
        xaddrs = _tag(xml, "XAddrs")
        dev = devices.setdefault(ip, OnvifDevice(ip=ip))
        dev.xaddr = xaddrs.split()[0] if xaddrs else dev.xaddr
        dev.scopes = _tag(xml, "Scopes")
        m = re.search(r"onvif://www\.onvif\.org/hardware/([^\s<]+)", dev.scopes)
        if m:
            dev.model = m.group(1)
        m = re.search(r"onvif://www\.onvif\.org/name/([^\s<]+)", dev.scopes)
        if m:
            dev.manufacturer = m.group(1).replace("_", " ")
    return list(devices.values())


# --------------------------------------------------------------------------
# SOAP transport
# --------------------------------------------------------------------------

async def _soap(xaddr: str, body: str, timeout: float = 3.0) -> str:
    m = re.match(r"https?://([^:/]+)(?::(\d+))?(/.*)?$", xaddr)
    if not m:
        return ""
    host = m.group(1)
    port = int(m.group(2) or 80)
    path = m.group(3) or "/"
    payload = _SOAP.format(body=body).encode()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Content-Type: application/soap+xml; charset=utf-8\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n\r\n").encode()
        writer.write(head + payload)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(1 << 20), timeout)
        text = raw.decode("utf-8", "replace")
        _, _, body_text = text.partition("\r\n\r\n")
        return body_text
    except Exception:
        return ""
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# rungs 2-3
# --------------------------------------------------------------------------

async def get_device_information(dev: OnvifDevice) -> OnvifDevice:
    xml = await _soap(dev.xaddr, "<tds:GetDeviceInformation/>")
    if xml:
        dev.manufacturer = _tag(xml, "Manufacturer") or dev.manufacturer
        dev.model = _tag(xml, "Model") or dev.model
        dev.firmware = _tag(xml, "FirmwareVersion") or dev.firmware
        dev.serial = _tag(xml, "SerialNumber") or dev.serial
    return dev


async def get_profiles(dev: OnvifDevice) -> List[dict]:
    xml = await _soap(dev.xaddr, "<trt:GetProfiles/>")
    profiles = []
    for block in re.findall(r"<(?:\w+:)?Profiles\b(.*?)</(?:\w+:)?Profiles>",
                            xml, re.S):
        m = re.search(r'token="([^"]+)"', block)
        token = m.group(1) if m else ""
        w = _tag(block, "Width")
        h = _tag(block, "Height")
        profiles.append({
            "token": token,
            "name": _tag(block, "Name"),
            "encoding": _tag(block, "Encoding"),
            "width": int(w) if w.isdigit() else 0,
            "height": int(h) if h.isdigit() else 0,
        })
    dev.profiles = profiles
    return profiles


async def get_stream_uri(dev: OnvifDevice, token: str) -> str:
    xml = await _soap(dev.xaddr, (
        "<trt:GetStreamUri>"
        "<trt:StreamSetup>"
        "<tt:Stream xmlns:tt='http://www.onvif.org/ver10/schema'>RTP-Unicast</tt:Stream>"
        "<tt:Transport xmlns:tt='http://www.onvif.org/ver10/schema'>"
        "<tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
        "</trt:StreamSetup>"
        f"<trt:ProfileToken>{token}</trt:ProfileToken>"
        "</trt:GetStreamUri>"))
    return _tag(xml, "Uri")


async def interrogate(dev: OnvifDevice) -> OnvifDevice:
    """Full rung 2 + 3: identity, then every profile's authoritative URL."""
    await get_device_information(dev)
    await get_profiles(dev)
    for prof in dev.profiles:
        prof["uri"] = await get_stream_uri(dev, prof["token"])
    return dev


def candidate_xaddr(ip: str, port: int = 8000) -> str:
    return f"http://{ip}:{port}/onvif/device_service"
