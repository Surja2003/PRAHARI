"""Where the simulated DVRs listen.

Linux routes the whole 127.0.0.0/8 block to the loopback interface, so each
fake DVR can own its own address and a genuine subnet scan finds them the
way it would find real hardware. Windows and macOS route only 127.0.0.1, so
that layout simply cannot bind there.

Rather than pick one and hope, probe: bind an alias, and if the kernel
refuses, fall back to giving every device the same address and separating
them by port. The discovery ladder handles both, because it was already
built to take a port per endpoint.

    alias mode   127.0.0.11:554, 127.0.0.12:554, ...   (Linux)
    port mode    127.0.0.1:8554, 127.0.0.1:8555, ...   (Windows, macOS)

Port mode loses two things, honestly and by necessity:
  * WS-Discovery, because only one listener can hold UDP 3702 on one
    address. The ladder falls through to probing the ONVIF port directly.
  * The vendor-specific fingerprint ports (37777 and friends), because
    several devices sharing an address would collide on them.
"""
from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass
from typing import List

log = logging.getLogger("prahari.sim.endpoints")

#: In a container the simulator must bind the container's own address, not
#: loopback, or nothing outside the container can reach it. Compose sets
#: PRAHARI_SIM_HOST to the service's static IP.
ALIAS_BASE = "127.0.0."
ALIAS_FIRST = 11
PORT_MODE_HOST = os.environ.get("PRAHARI_SIM_HOST", "127.0.0.1")
PORT_RTSP_BASE = 8554
PORT_HTTP_BASE = 8580
PORT_ONVIF_BASE = 8600


@dataclass
class Endpoint:
    ip: str
    rtsp_port: int
    http_port: int
    onvif_port: int
    alias_mode: bool

    @property
    def target(self) -> str:
        """How discovery should be told to look for this device."""
        return (self.ip if self.rtsp_port == 554
                else f"{self.ip}:{self.rtsp_port}")


def _can_bind(ip: str, port: int) -> bool:
    for family, sock_type in ((socket.AF_INET, socket.SOCK_STREAM),):
        s = socket.socket(family, sock_type)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, port))
            return True
        except OSError:
            return False
        finally:
            s.close()
    return False


def alias_supported(count: int = 1) -> bool:
    """Can this OS give each simulated DVR its own loopback address?

    Checks a real bind rather than sniffing the platform name, because
    a Windows machine *can* be configured with extra loopback addresses
    and a Linux container can be locked down.
    """
    if os.environ.get("PRAHARI_SIM_MODE", "").lower() == "port":
        return False
    if os.environ.get("PRAHARI_SIM_MODE", "").lower() == "alias":
        return True
    return all(_can_bind(f"{ALIAS_BASE}{ALIAS_FIRST + i}", 0)
               for i in range(count))


def allocate(count: int) -> List[Endpoint]:
    """One endpoint per device, in whichever mode this machine supports."""
    if alias_supported(count):
        eps = [Endpoint(ip=f"{ALIAS_BASE}{ALIAS_FIRST + i}", rtsp_port=554,
                        http_port=80, onvif_port=8000, alias_mode=True)
               for i in range(count)]
        # Privileged ports still need the capability, even in alias mode.
        if not _can_bind(eps[0].ip, 554):
            log.warning("loopback aliases work but port 554 is refused "
                        "(needs root or CAP_NET_BIND_SERVICE); using ports")
        else:
            log.info("simulator in ALIAS mode: one address per DVR")
            return eps

    log.info("simulator in PORT mode: all DVRs on %s, separated by port "
             "(this OS routes only 127.0.0.1 to loopback)", PORT_MODE_HOST)
    return [Endpoint(ip=PORT_MODE_HOST,
                     rtsp_port=PORT_RTSP_BASE + i,
                     http_port=PORT_HTTP_BASE + i,
                     onvif_port=PORT_ONVIF_BASE + i,
                     alias_mode=False)
            for i in range(count)]


def scan_spec(endpoints: List[Endpoint]) -> str:
    """The host spec to hand the discovery ladder for these endpoints.

    In alias mode this is a real subnet, because scanning one is the point.
    In port mode it is the explicit endpoint list -- there is no subnet to
    sweep when every device shares an address.
    """
    if endpoints and endpoints[0].alias_mode:
        return "127.0.0.0/24"
    return ",".join(e.target for e in endpoints)
