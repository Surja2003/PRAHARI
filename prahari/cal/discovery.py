"""The discovery ladder.

Seven rungs, tried in order, stopping at the first that yields a playable
stream. Rungs 1-3 are the polite standards-based path. Rungs 4-7 are what
make it work on field hardware that shipped with ONVIF switched off.

Every rung records what it tried and what it learned, because the ladder's
reasoning is itself the demo: an operator pressing "Scan network" should be
able to see exactly how each device was identified.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from . import onvif_client as onvif
from .brands import Brand, BrandLibrary, Credential, load, match_brand
from .optics import Capability, Optics, Role, assess
from .probe import (RtspResult, arp_lookup, http_banner, oui_of, probe_many,
                    redact, rtsp_describe, scan_ports)

log = logging.getLogger("prahari.cal.discovery")

MAX_CHANNELS = 32


@dataclass
class LadderStep:
    rung: int
    name: str
    outcome: str
    detail: str = ""
    elapsed_ms: int = 0

    def as_dict(self) -> dict:
        return {"rung": self.rung, "name": self.name, "outcome": self.outcome,
                "detail": self.detail, "elapsed_ms": self.elapsed_ms}


@dataclass
class DiscoveredStream:
    channel: int
    which: str                 # "main" | "sub"
    url: str
    width: int = 0
    height: int = 0
    fps: float = 0.0
    codec: str = ""

    def as_dict(self) -> dict:
        return {"channel": self.channel, "which": self.which,
                "url": redact(self.url), "width": self.width,
                "height": self.height, "fps": self.fps, "codec": self.codec}


@dataclass
class DiscoveredDevice:
    ip: str
    port: int = 554
    brand: str = ""
    label: str = ""
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    mac: str = ""
    open_ports: List[int] = field(default_factory=list)
    server_header: str = ""
    onvif_xaddr: str = ""
    identified_by: str = ""
    credential: Optional[Credential] = None
    streams: List[DiscoveredStream] = field(default_factory=list)
    ladder: List[LadderStep] = field(default_factory=list)
    templates_tried: int = 0

    @property
    def channels(self) -> List[int]:
        return sorted({s.channel for s in self.streams})

    def stream_for(self, channel: int, which: str) -> Optional[DiscoveredStream]:
        for s in self.streams:
            if s.channel == channel and s.which == which:
                return s
        return None

    def as_dict(self) -> dict:
        return {
            "ip": self.ip, "port": self.port, "brand": self.brand,
            "label": self.label, "manufacturer": self.manufacturer,
            "model": self.model, "firmware": self.firmware,
            "serial": self.serial, "mac": self.mac,
            "open_ports": self.open_ports, "server": self.server_header,
            "onvif": bool(self.onvif_xaddr),
            "identified_by": self.identified_by,
            "credential": self.credential.as_dict() if self.credential else None,
            "channels": self.channels,
            "streams": [s.as_dict() for s in self.streams],
            "ladder": [s.as_dict() for s in self.ladder],
            "templates_tried": self.templates_tried,
        }


@dataclass
class DiscoveryReport:
    devices: List[DiscoveredDevice] = field(default_factory=list)
    hosts_scanned: int = 0
    elapsed_ms: int = 0

    def as_dict(self) -> dict:
        return {"devices": [d.as_dict() for d in self.devices],
                "hosts_scanned": self.hosts_scanned,
                "elapsed_ms": self.elapsed_ms,
                "cameras": sum(len(d.channels) for d in self.devices)}


DEFAULT_RTSP_PORT = 554


def expand_hosts(spec: str) -> List[Tuple[str, int]]:
    """Parse a target spec into (ip, rtsp_port) pairs.

    Accepts, in any comma-separated combination:
        127.0.0.0/24            a subnet, port 554
        10.0.0.5-10.0.0.60      an address range, port 554
        192.168.1.64:8554       one endpoint on a non-standard port
        127.0.0.1:8554-8557     a port range on one address

    The port forms matter more than they look. Several DVRs behind one NAT
    are commonly port-forwarded onto a single public address, and the
    simulator does the same thing on any OS that routes only 127.0.0.1 to
    loopback -- Windows and macOS both do.
    """
    out: List[Tuple[str, int]] = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            out.extend((str(h), DEFAULT_RTSP_PORT) for h in net.hosts())
            continue
        # ip:port or ip:portA-portB
        m = re.match(r"^([0-9.]+):(\d+)(?:-(\d+))?$", part)
        if m:
            ip = m.group(1)
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
            out.extend((ip, p) for p in range(lo, hi + 1))
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            start = int(ipaddress.ip_address(a.strip()))
            end = int(ipaddress.ip_address(b.strip()))
            out.extend((str(ipaddress.ip_address(i)), DEFAULT_RTSP_PORT)
                       for i in range(start, end + 1))
            continue
        out.append((part, DEFAULT_RTSP_PORT))
    return out


class Discoverer:
    def __init__(self, library: Optional[BrandLibrary] = None,
                 credentials: Optional[List[Credential]] = None,
                 timeout: float = 2.0, concurrency: int = 128):
        self.lib = library or load()
        self.credentials = credentials or self.lib.default_credentials
        self.timeout = timeout
        self.concurrency = concurrency

    # ------------------------------------------------------------------
    async def scan(self, hosts_spec: str = "127.0.0.0/24",
                   max_channels: int = 8) -> DiscoveryReport:
        t0 = time.monotonic()
        targets = expand_hosts(hosts_spec)
        report = DiscoveryReport(hosts_scanned=len(targets))
        unique_ips = sorted({ip for ip, _ in targets})

        # ---- rung 1: WS-Discovery ------------------------------------
        t = time.monotonic()
        onvif_devices = await onvif.ws_discover(targets=unique_ips, timeout=1.5)
        ws_ms = int((time.monotonic() - t) * 1000)
        onvif_by_ip = {d.ip: d for d in onvif_devices}
        log.info("rung 1: WS-Discovery found %d device(s) in %d ms",
                 len(onvif_devices), ws_ms)

        # ---- rung 4 (run early, in parallel): port sweep --------------
        # Cheap, and its results feed the brand prior for every later rung.
        t = time.monotonic()
        live = await self._sweep(targets)
        sweep_ms = int((time.monotonic() - t) * 1000)
        log.info("rung 4: %d endpoint(s) with RTSP open, swept %d in %d ms",
                 len(live), len(targets), sweep_ms)

        self._per_ip = {}
        for ip, _p in live:
            self._per_ip[ip] = self._per_ip.get(ip, 0) + 1

        for (ip, rtsp_port), open_ports in sorted(live.items()):
            dev = DiscoveredDevice(ip=ip, port=rtsp_port,
                                   open_ports=open_ports)
            dev.ladder.append(LadderStep(
                1, "WS-Discovery multicast + unicast probe",
                "hit" if ip in onvif_by_ip else "miss",
                "device announced itself" if ip in onvif_by_ip
                else "no ProbeMatch; ONVIF likely disabled", ws_ms))
            dev.ladder.append(LadderStep(
                4, "Subnet sweep and port fingerprint", "hit",
                "open: " + ", ".join(str(p) for p in open_ports), sweep_ms))

            od = onvif_by_ip.get(ip)
            if od is None:
                # No ProbeMatch does not mean no ONVIF: WS-Discovery is
                # multicast, and it cannot work at all when several devices
                # share one address. Probe the likely service ports directly
                # before giving up on the standards path.
                od = await self._probe_onvif(dev)
            if od is not None:
                await self._via_onvif(dev, od, max_channels)
            if not dev.streams:
                await self._via_templates(dev, max_channels)
            report.devices.append(dev)

        report.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return report

    # ------------------------------------------------------------------
    def _endpoints_on(self, ip: str) -> int:
        return getattr(self, "_per_ip", {}).get(ip, 1)

    def _shared_address(self, ip: str) -> bool:
        return self._endpoints_on(ip) > 1

    #: Ports worth fingerprinting once RTSP has answered. The 85xx/86xx
    #: block is the simulator's port mode; the rest are real vendor ports.
    AUX_PORTS = [80, 8000, 8080, 8899, 37777, 1756, 4520,
                 8580, 8581, 8582, 8583, 8600, 8601, 8602, 8603]

    async def _sweep(self, targets: List[Tuple[str, int]]
                     ) -> Dict[Tuple[str, int], List[int]]:
        """Find endpoints with RTSP open, then fingerprint their other ports."""
        sem = asyncio.Semaphore(self.concurrency)
        aux_cache: Dict[str, List[int]] = {}
        aux_lock = asyncio.Lock()

        async def check(ip: str, rtsp_port: int):
            async with sem:
                ports = await scan_ports(ip, [rtsp_port], timeout=0.4)
                if not ports:
                    return (ip, rtsp_port), None
            # Auxiliary ports belong to the address, not the RTSP endpoint,
            # so scan them once per address however many DVRs sit behind it.
            async with aux_lock:
                if ip not in aux_cache:
                    aux_cache[ip] = await scan_ports(ip, self.AUX_PORTS,
                                                     timeout=0.4)
            return (ip, rtsp_port), sorted(set(ports + aux_cache[ip]))

        results = await asyncio.gather(*(check(ip, p) for ip, p in targets))
        return {key: ports for key, ports in results if ports}

    # ------------------------------------------------------------------
    async def _probe_onvif(self, dev: DiscoveredDevice):
        """Find the ONVIF service belonging to THIS RTSP endpoint.

        An auxiliary port belongs to an address, not to an RTSP endpoint.
        When several DVRs sit behind one address -- normal behind NAT, and
        unavoidable on an OS that routes only 127.0.0.1 -- answering "the
        first ONVIF service that replies" attributes every camera to
        whichever device happens to answer first.

        The only sound test is to make the service prove ownership: ask for
        its stream URIs and keep it only if they point back at this exact
        RTSP port.
        """
        candidates = [p for p in (8000, 8899, 80, 8080, 8600, 8601, 8602,
                                  8603, 8604, 8605)
                      if p in dev.open_ports]
        for port in candidates:
            od = onvif.OnvifDevice(ip=dev.ip,
                                   xaddr=onvif.candidate_xaddr(dev.ip, port))
            await onvif.get_device_information(od)
            if not (od.manufacturer or od.model):
                continue
            await onvif.get_profiles(od)
            uri = ""
            for prof in od.profiles:
                uri = await onvif.get_stream_uri(od, prof.get("token", ""))
                if uri:
                    break
            if not uri:
                continue
            claimed = urlsplit(uri)
            if claimed.port and claimed.port != dev.port:
                log.debug("ONVIF at %s:%d serves port %s, not %d -- skipping",
                          dev.ip, port, claimed.port, dev.port)
                continue
            for prof in od.profiles:
                prof["uri"] = prof.get("uri") or await onvif.get_stream_uri(
                    od, prof.get("token", ""))
            dev.ladder.append(LadderStep(
                2, "ONVIF service located by probe", "hit",
                f"port {port} claims the streams on :{dev.port}"))
            return od
        return None

    # ------------------------------------------------------------------
    async def _via_onvif(self, dev: DiscoveredDevice,
                         od: onvif.OnvifDevice, max_channels: int):
        """Rungs 2 and 3 -- the device tells us its own URLs."""
        t = time.monotonic()
        if not od.xaddr:
            od.xaddr = onvif.candidate_xaddr(dev.ip)
        if not od.profiles:
            await onvif.interrogate(od)
        ms = int((time.monotonic() - t) * 1000)

        if not od.manufacturer and not od.profiles:
            dev.ladder.append(LadderStep(
                2, "ONVIF GetDeviceInformation", "miss",
                "no SOAP response at " + od.xaddr, ms))
            return

        dev.onvif_xaddr = od.xaddr
        dev.manufacturer = od.manufacturer
        dev.model = od.model
        dev.firmware = od.firmware
        dev.serial = od.serial
        brand = match_brand(self.lib, od.manufacturer)
        if brand:
            dev.brand, dev.label = brand.key, brand.label
        dev.ladder.append(LadderStep(
            2, "ONVIF GetDeviceInformation", "hit",
            f"{od.manufacturer} {od.model} fw {od.firmware}", ms))

        if not od.profiles:
            dev.ladder.append(LadderStep(
                3, "ONVIF GetProfiles / GetStreamUri", "miss",
                "device exposed no media profiles"))
            return

        # Authoritative URLs, but they still need credentials to play.
        cred = await self._find_credential_for(
            [p.get("uri", "") for p in od.profiles if p.get("uri")])
        dev.credential = cred
        added = 0
        for prof in od.profiles:
            uri = prof.get("uri") or ""
            if not uri:
                continue
            ch, which = self._token_hint(prof.get("token", ""), prof)
            if ch > max_channels:
                continue
            authed = self._with_credentials(uri, cred) if cred else uri
            dev.streams.append(DiscoveredStream(
                channel=ch, which=which, url=authed,
                width=prof.get("width", 0), height=prof.get("height", 0),
                codec=prof.get("encoding", "")))
            added += 1
        dev.identified_by = "onvif"
        dev.ladder.append(LadderStep(
            3, "ONVIF GetProfiles / GetStreamUri", "hit",
            f"{added} authoritative stream URL(s) returned by the device"))

    @staticmethod
    def _token_hint(token: str, prof: dict):
        ch, which = 1, "main"
        parts = token.split("_")
        if len(parts) >= 3 and parts[1].isdigit():
            ch, which = int(parts[1]), parts[2]
        elif prof.get("width") and prof["width"] < 900:
            which = "sub"
        return ch, which

    # ------------------------------------------------------------------
    async def _via_templates(self, dev: DiscoveredDevice, max_channels: int):
        """Rungs 5, 6, 7 -- fingerprint, probe templates, enumerate channels."""
        # rung 5: MAC OUI
        t = time.monotonic()
        mac = await arp_lookup(dev.ip)
        dev.mac = mac
        oui = oui_of(mac)
        dev.ladder.append(LadderStep(
            5, "MAC OUI lookup", "hit" if oui else "miss",
            f"OUI {oui}" if oui else "no ARP entry for this address",
            int((time.monotonic() - t) * 1000)))

        # HTTP banner sharpens the prior (part of rung 4's fingerprint)
        title = ""
        if self._shared_address(dev.ip):
            # A web UI on a shared address cannot be tied to one RTSP
            # endpoint, and guessing merges devices. Say so rather than
            # silently attributing another box's badge to this one.
            dev.ladder.append(LadderStep(
                4, "HTTP banner", "skip",
                f"{self._endpoints_on(dev.ip)} RTSP endpoints share {dev.ip}; "
                "a web UI cannot be attributed to one of them"))
        else:
            for port in [p for p in (80, 8080, 8000) if p in dev.open_ports]:
                server, title = await http_banner(dev.ip, port)
                if server or title:
                    dev.server_header = server or dev.server_header
                    dev.ladder.append(LadderStep(
                        4, "HTTP banner", "hit",
                        f":{port} Server: {server}"
                        + (f" | title: {title}" if title else "")))
                    break

        # The RTSP Server header is the one fingerprint that always belongs
        # to THIS endpoint, however many devices share the address.
        t = time.monotonic()
        banner = await rtsp_describe(f"rtsp://{dev.ip}:{dev.port}/", 1.5)
        if banner.server:
            dev.server_header = dev.server_header or banner.server
            dev.ladder.append(LadderStep(
                4, "RTSP banner", "hit", f"Server: {banner.server}",
                int((time.monotonic() - t) * 1000)))

        order = self.lib.ordered(dev.open_ports, oui, dev.server_header, title)

        # rung 6: parallel DESCRIBE across brand templates, channel 1
        t = time.monotonic()
        winner: Optional[tuple] = None
        tried = 0
        for cred in self.credentials:
            urls, owners = [], []
            for brand in order:
                for u in brand.expand(dev.ip, cred, channel=1, port=dev.port):
                    urls.append(u)
                    owners.append(brand)
            tried += len(urls)
            results = await probe_many(urls, concurrency=24,
                                       timeout=self.timeout)
            for res, brand in zip(results, owners):
                if res.ok:
                    winner = (brand, cred, res)
                    break
            if winner:
                break
            # If every template came back 401 rather than 404, the paths are
            # right and only the password is wrong -- keep trying credentials.
            if not any(r.unauthorized for r in results):
                continue

        dev.templates_tried = tried
        ms = int((time.monotonic() - t) * 1000)
        if not winner:
            dev.ladder.append(LadderStep(
                6, "Brand template probing", "miss",
                f"{tried} template(s) tried, none answered 200", ms))
            return

        brand, cred, res = winner
        dev.brand = dev.brand or brand.key
        dev.label = dev.label or brand.label
        dev.credential = cred
        dev.identified_by = dev.identified_by or "template"
        dev.server_header = dev.server_header or res.server
        if not dev.manufacturer:
            dev.manufacturer = brand.label
        if not dev.model and title:
            # "CP Plus CP-UVR-0801E1-CS" -> model is whatever follows the brand
            tail = re.sub(r"^\s*" + re.escape(brand.label) + r"\s*", "",
                          title, flags=re.I).strip()
            dev.model = tail or title
        detail = (f"{brand.label} matched after {tried} template(s); "
                  f"first 200 OK in {res.elapsed_ms} ms")
        # Several vendors ship the same firmware under their own badge --
        # CP Plus is Dahua, Amcrest is Dahua. The dialect and the RTSP
        # Server header are identical; only the web UI carries the badge.
        # Say which family we are sure of rather than guess the label.
        siblings = [b.label for b in self.lib.brands.values()
                    if b.key != brand.key and b.templates == brand.templates]
        if siblings and self._shared_address(dev.ip):
            detail += (f" -- {brand.label}-family dialect; the OEM badge "
                       f"({', '.join(siblings)}) is only on the device web "
                       f"UI, unattributable on a shared address")
        dev.ladder.append(LadderStep(
            6, "Brand template probing", "hit", detail, ms))

        # rung 7: channel enumeration
        t = time.monotonic()
        await self._enumerate(dev, brand, cred, max_channels)
        dev.ladder.append(LadderStep(
            7, "Channel enumeration", "hit",
            f"{len(dev.channels)} channel(s) live on this device",
            int((time.monotonic() - t) * 1000)))

    async def _enumerate(self, dev: DiscoveredDevice, brand: Brand,
                         cred: Credential, max_channels: int):
        """Walk channels until two consecutive misses."""
        misses = 0
        for ch in range(1, min(max_channels, MAX_CHANNELS) + 1):
            urls = brand.expand(dev.ip, cred, channel=ch, port=dev.port)
            results = await probe_many(urls, concurrency=8,
                                       timeout=self.timeout)
            good = [r for r in results if r.ok]
            if not good:
                misses += 1
                if misses >= 2:
                    break
                continue
            misses = 0
            # Several templates can resolve to the SAME stream (Hikvision's
            # legacy /h264/chN/main path is the modern /Streaming path under
            # another name), so collapse by resolution before deciding which
            # is main and which is the substream.
            unique, seen = [], set()
            for r in sorted(good, key=lambda r: r.width * r.height,
                            reverse=True):
                key = (r.width, r.height)
                if key in seen:
                    continue
                seen.add(key)
                unique.append(r)
            for idx, r in enumerate(unique[:2]):
                dev.streams.append(DiscoveredStream(
                    channel=ch, which="main" if idx == 0 else "sub",
                    url=r.url, width=r.width, height=r.height,
                    fps=r.fps, codec=r.codec))

    # ------------------------------------------------------------------
    async def _find_credential_for(self, urls: List[str]) -> Optional[Credential]:
        """ONVIF hands back URLs without credentials; find one that plays."""
        if not urls:
            return None
        for cred in self.credentials:
            res = await rtsp_describe(self._with_credentials(urls[0], cred),
                                      self.timeout)
            if res.ok:
                return cred
        return None

    @staticmethod
    def _with_credentials(url: str, cred: Credential) -> str:
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            return url
        scheme, _, rest = url.partition("://")
        return f"{scheme}://{cred.user}:{cred.password}@{rest}"


async def discover(hosts: str = "127.0.0.0/24",
                   max_channels: int = 8) -> DiscoveryReport:
    return await Discoverer().scan(hosts, max_channels)
