"""The simulated DVR farm.

Four devices, each on its own loopback address so that a genuine subnet
scan finds them, each speaking its own brand's RTSP dialect:

  127.0.0.11  Hikvision DS-7208HQHI-K1   4 ch  digest  ONVIF OFF
  127.0.0.12  CP Plus  CP-UVR-0801E1-CS  2 ch  digest  ONVIF OFF
  127.0.0.13  Uniview  NVR301-08S3       2 ch  basic   ONVIF ON
  127.0.0.14  Axis     P1435-LE          1 ch  digest  ONVIF ON

Two of them have ONVIF disabled on purpose. That is the normal state of
shipped field hardware, and it is what forces the discovery ladder down to
port fingerprinting and template probing -- the part worth demonstrating.

Also exposes a small control API (127.0.0.1:9099) so the dashboard can
degrade a device's link live: fibre -> P2P wireless -> 4G -> outage.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, List

from .endpoints import Endpoint, allocate, scan_spec
from .footage import build_all
from .onvif_responder import HttpService, WsDiscoveryResponder
from .dialects import DIALECTS
from .rtsp_server import (PRESETS, Channel, DvrDevice, LinkProfile,
                          RtspServer, load_stream)

#: Vendor fingerprint ports, bound only in alias mode.
DIALECT_EXTRA = {k: v.extra_ports for k, v in DIALECTS.items()}

log = logging.getLogger("prahari.sim.farm")

CONTROL_HOST = os.environ.get("PRAHARI_FARM_HOST", "127.0.0.1")
CONTROL_PORT = 9099


@dataclass
class DeviceSpec:
    ip: str
    brand: str
    serial: str
    onvif: bool
    user: str
    password: str
    # (channel number, display name, scene key, role hint)
    channels: List[tuple]


FARM: List[DeviceSpec] = [
    DeviceSpec("127.0.0.11", "hikvision", "DS7208-SIM-0001", False, "admin", "admin", [
        (1, "BOP-7 North Face",   "perimeter_day",   "perimeter"),
        (2, "BOP-7 Track West",   "perimeter_day",   "perimeter"),
        (3, "BOP-7 North Night",  "perimeter_night", "perimeter"),
        (4, "BOP-7 Main Gate",    "gate_day",        "chokepoint"),
    ]),
    DeviceSpec("127.0.0.12", "cpplus", "CPUVR-SIM-0002", False, "admin", "admin12345", [
        (1, "BOP-9 River Bank",   "perimeter_day",   "perimeter"),
        (2, "BOP-9 Barrier",      "gate_day",        "chokepoint"),
    ]),
    DeviceSpec("127.0.0.13", "uniview", "UNV301-SIM-0003", True, "admin", "admin", [
        (1, "ICP Approach Road",  "gate_day",        "chokepoint"),
        (2, "ICP Perimeter East", "perimeter_day",   "perimeter"),
    ]),
    DeviceSpec("127.0.0.14", "axis", "AXIS-SIM-0004", True, "root", "root", [
        (1, "Sector HQ Yard",     "perimeter_day",   "perimeter"),
    ]),
]


class DvrFarm:
    def __init__(self, media_dir: str = "media"):
        self.media_dir = media_dir
        self.endpoints: List[Endpoint] = []
        self.devices: Dict[str, DvrDevice] = {}
        self.rtsp: List[RtspServer] = []
        self.http: List[HttpService] = []
        self.udp: List = []
        self.control = None

    # ------------------------------------------------------------------
    def build(self):
        scenes = build_all(self.media_dir)
        self.endpoints = allocate(len(FARM))
        for spec, ep in zip(FARM, self.endpoints):
            channels: Dict[int, Channel] = {}
            for number, name, scene, role in spec.channels:
                main_path, main_spec = scenes[scene]
                sub_key = f"{scene}_sub"
                sub_path, sub_spec = scenes.get(sub_key, (main_path, main_spec))
                channels[number] = Channel(
                    number=number, name=name,
                    main=load_stream(main_path, main_spec.fps,
                                     main_spec.width, main_spec.height),
                    sub=load_stream(sub_path, sub_spec.fps,
                                    sub_spec.width, sub_spec.height),
                    role_hint=role,
                )
            dev = DvrDevice(
                ip=ep.ip, brand=spec.brand, channels=channels,
                username=spec.user, password=spec.password,
                port=ep.rtsp_port,
                serial=spec.serial, onvif_enabled=spec.onvif,
                link=LinkProfile(**PRESETS["fibre"].snapshot()),
                http_port=ep.http_port, onvif_port=ep.onvif_port,
                extra_ports=(tuple(DIALECT_EXTRA.get(spec.brand, ()))
                             if ep.alias_mode else ()),
            )
            self.devices[dev.key] = dev
        return self

    async def start(self):
        if not self.devices:
            self.build()
        alias_mode = bool(self.endpoints and self.endpoints[0].alias_mode)
        for dev in self.devices.values():
            self.rtsp.append(await RtspServer(dev).start())
            self.http.append(
                await HttpService(dev, dev.http_port, onvif=False).start())
            if dev.onvif_enabled:
                self.http.append(
                    await HttpService(dev, dev.onvif_port, onvif=True).start())
                if alias_mode:
                    # Only one listener can hold UDP 3702 per address, so
                    # WS-Discovery is an alias-mode feature. In port mode the
                    # ladder falls through to probing the ONVIF port directly.
                    transport, _ = await WsDiscoveryResponder.start(dev)
                    if transport:
                        self.udp.append(transport)
            # A listening vendor port is what makes fingerprinting honest:
            # Hikvision answers on 8000, Dahua/CP Plus on 37777. Several
            # devices sharing one address would collide, so alias mode only.
            for port in dev.extra_ports:
                if port in (dev.http_port, dev.onvif_port):
                    continue
                self.http.append(
                    await HttpService(dev, port, onvif=False).start())
        self.control = await asyncio.start_server(
            self._control, CONTROL_HOST, CONTROL_PORT)
        log.info("farm up: %d devices, control on %s:%d",
                 len(self.devices), CONTROL_HOST, CONTROL_PORT)
        return self

    async def stop(self):
        for s in self.rtsp:
            await s.stop()
        for h in self.http:
            await h.stop()
        for t in self.udp:
            t.close()
        if self.control:
            self.control.close()

    # ------------------------------------------------------------------
    # control API: GET /devices, POST /link {ip, preset}
    # ------------------------------------------------------------------
    async def _control(self, reader, writer):
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
            body = b""
            n = int(headers.get("content-length", 0) or 0)
            if n:
                body = await reader.readexactly(n)

            if path.startswith("/devices"):
                payload = {
                    "devices": [d.describe() for d in self.devices.values()],
                    "presets": list(PRESETS),
                    "scan_spec": scan_spec(self.endpoints),
                    "mode": ("alias" if self.endpoints
                             and self.endpoints[0].alias_mode else "port"),
                }
            elif path.startswith("/link") and method == "POST":
                req = json.loads(body or b"{}")
                ip = req.get("ip")
                preset = req.get("preset", "fibre")
                targets = ([self.devices[ip]] if ip in self.devices
                           else [d for d in self.devices.values()
                                 if d.ip == ip] or list(self.devices.values()))
                base = PRESETS.get(preset)
                if not base:
                    payload = {"error": f"unknown preset {preset!r}"}
                else:
                    for dev in targets:
                        for k, v in base.snapshot().items():
                            setattr(dev.link, k, v)
                    payload = {"ok": True, "preset": preset,
                               "applied_to": [d.ip for d in targets]}
            elif path.startswith("/stats"):
                payload = {"servers": [
                    {"ip": s.dev.ip, "port": s.dev.port, **s.stats}
                    for s in self.rtsp]}
            else:
                payload = {"error": "not found"}

            raw = json.dumps(payload).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Access-Control-Allow-Origin: *\r\n"
                         + f"Content-Length: {len(raw)}\r\n".encode()
                         + b"Connection: close\r\n\r\n" + raw)
            await writer.drain()
        except Exception:
            log.exception("control error")
        finally:
            try:
                writer.close()
            except Exception:
                pass


async def main():
    logging.basicConfig(
        level=os.environ.get("PRAHARI_LOG", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s")
    farm = await DvrFarm().start()
    print("\n  Simulated DVR farm running\n")
    mode = "ALIAS" if farm.endpoints[0].alias_mode else "PORT"
    print(f"  mode: {mode}\n")
    for dev in farm.devices.values():
        d = dev.dialect
        print(f"   {dev.key:20s} {d.label:10s} {d.model:20s} "
              f"{len(dev.channels)} ch  auth={d.auth:6s} "
              f"onvif={'on ' if dev.onvif_enabled else 'off'} "
              f"{dev.username}:{dev.password}")
    print(f"\n   scan with:   {scan_spec(farm.endpoints)}")
    print(f"   control api  http://{CONTROL_HOST}:{CONTROL_PORT}/devices\n")
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await farm.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
