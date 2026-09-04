"""The brand URL library: load config/brands.yaml and expand templates.

Adding a vendor is a change to the YAML, never to this module. That is the
whole contract -- the field engineer who meets an unknown DVR at a border
outpost should be able to add it with a text editor.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional

import yaml

DEFAULT_PATH = os.environ.get(
    "PRAHARI_BRANDS",
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "brands.yaml"))


@dataclass
class Credential:
    user: str
    password: str

    def as_dict(self) -> dict:
        return {"user": self.user, "password": "****" if self.password else ""}


@dataclass
class Brand:
    key: str
    label: str
    aliases: List[str]
    auth: str
    realm: str
    server_header: str
    stream_codes: Dict[str, str]
    templates: List[str]
    ports: List[int]
    ouis: List[str]
    server_hints: List[str]

    def expand(self, ip: str, cred: Credential, channel: int = 1,
               port: int = 554) -> List[str]:
        out: List[str] = []
        subs = {
            "ip": ip, "port": port,
            "user": cred.user, "pass": cred.password,
            "ch": channel, "ch0": max(channel - 1, 0),
            "main": self.stream_codes.get("main", "0"),
            "sub": self.stream_codes.get("sub", "1"),
        }
        for tpl in self.templates:
            try:
                out.append(tpl.format(**subs))
            except (KeyError, ValueError, IndexError):
                continue
        return out

    def score(self, open_ports: List[int], oui: str, server: str,
              banner: str = "") -> float:
        """Prior that an unidentified device is this brand.

        `banner` is the device's HTTP page title. It matters more than it
        looks: OEM rebrands (CP Plus is Dahua hardware) keep the original
        vendor's Server header and RTSP dialect, and the only place the
        actual badge on the box appears is the login page title.
        """
        s = 0.0
        for p in self.ports:
            if p in open_ports and p not in (554, 80):
                s += 2.0            # a vendor-specific port is strong evidence
            elif p in open_ports:
                s += 0.2
        if oui and oui.lower() in [o.lower() for o in self.ouis]:
            s += 5.0
        low = (server or "").lower()
        for hint in self.server_hints:
            if hint and hint.lower() in low:
                s += 3.0
        blow = (banner or "").lower()
        if blow:
            names = [self.key, self.label.lower()] + list(self.aliases)
            if any(n and n in blow for n in names):
                s += 6.0            # the badge on the box beats the chipset
        return s


@dataclass
class BrandLibrary:
    brands: Dict[str, Brand] = field(default_factory=dict)
    default_credentials: List[Credential] = field(default_factory=list)
    version: int = 0

    def ordered(self, open_ports: List[int], oui: str = "",
                server: str = "", banner: str = "") -> List[Brand]:
        """Brands most likely first; 'generic' always last."""
        ranked = sorted(
            (b for b in self.brands.values() if b.key != "generic"),
            key=lambda b: b.score(open_ports, oui, server, banner),
            reverse=True)
        if "generic" in self.brands:
            ranked.append(self.brands["generic"])
        return ranked

    def get(self, key: str) -> Optional[Brand]:
        return self.brands.get(key)


@lru_cache(maxsize=4)
def load(path: str = DEFAULT_PATH) -> BrandLibrary:
    with open(os.path.abspath(path)) as fh:
        raw = yaml.safe_load(fh)
    lib = BrandLibrary(version=raw.get("version", 0))
    for key, spec in (raw.get("brands") or {}).items():
        fp = spec.get("fingerprint") or {}
        lib.brands[key] = Brand(
            key=key,
            label=spec.get("label", key.title()),
            aliases=[a.lower() for a in (spec.get("aliases") or [])],
            auth=spec.get("auth", "basic"),
            realm=spec.get("realm", ""),
            server_header=spec.get("server_header", ""),
            stream_codes=spec.get("stream_codes") or {},
            templates=spec.get("templates") or [],
            ports=fp.get("ports") or [554],
            ouis=fp.get("oui") or [],
            server_hints=fp.get("server") or [],
        )
    for c in (raw.get("default_credentials") or []):
        lib.default_credentials.append(
            Credential(c.get("user", ""), c.get("pass", "")))
    return lib


def match_brand(lib: BrandLibrary, manufacturer: str) -> Optional[Brand]:
    """Map an ONVIF manufacturer string onto a brand key."""
    m = (manufacturer or "").strip().lower()
    if not m:
        return None
    for brand in lib.brands.values():
        if brand.key in m or brand.label.lower() in m:
            return brand
        for alias in brand.aliases:
            if alias and alias in m:
                return brand
    return None


def all_ports(lib: BrandLibrary) -> List[int]:
    ports = set()
    for b in lib.brands.values():
        ports.update(b.ports)
    ports.update({554, 80, 8000, 8899, 37777, 3702})
    return sorted(ports)
