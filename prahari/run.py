"""Cross-platform launcher.

Windows has no make and no bash, so the shell scripts in scripts/ are
Linux-only conveniences. This starts the same three processes with nothing
but Python:

    python -m prahari.run demo      footage, DVR farm, mock C2, server
    python -m prahari.run farm      just the simulated DVRs
    python -m prahari.run server    just the control plane
    python -m prahari.run footage   render the synthetic footage and exit
    python -m prahari.run scan      print the discovery ladder to the console

`demo` prints the exact host spec to scan, because on Windows and macOS the
simulator runs in port mode and the target list is not 127.0.0.0/24.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
SERVER_URL = "http://127.0.0.1:8000"
FARM_URL = "http://127.0.0.1:9099"
C2_URL = "http://127.0.0.1:9200/events"

_children: List[subprocess.Popen] = []


def _spawn(args: List[str], log_name: str) -> subprocess.Popen:
    log_path = os.path.join(ROOT, f"{log_name}.log")
    fh = open(log_path, "w")
    kwargs = {}
    if os.name == "nt":
        # Own process group so Ctrl-C in this console does not race the
        # children before we get a chance to shut them down cleanly.
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(args, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                            **kwargs)
    _children.append(proc)
    print(f"    started {log_name} (pid {proc.pid})  log: {log_path}")
    return proc


def _stop_all():
    for p in _children:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    deadline = time.time() + 5
    for p in _children:
        while p.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass


atexit.register(_stop_all)


def _get(url: str, timeout: float = 3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _post(url: str, payload: dict, timeout: float = 240.0):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as exc:
        print(f"    ! {url} failed: {exc}")
        return None


def _wait_for(url: str, what: str, seconds: int = 90) -> Optional[dict]:
    for _ in range(seconds * 2):
        got = _get(url, timeout=2.0)
        if got is not None:
            return got
        time.sleep(0.5)
    print(f"    ! {what} did not come up within {seconds}s")
    return None


# --------------------------------------------------------------------------

def cmd_footage() -> int:
    from prahari.sim import footage
    print("\n  Rendering synthetic border footage (about a minute)…")
    for name, (path, spec) in footage.build_all(
            os.path.join(ROOT, "media")).items():
        size = os.path.getsize(path) / 1024
        print(f"    {name:22s} {spec.width}x{spec.height}@{spec.fps}  "
              f"{size:8.1f} KiB")
    return 0


def cmd_farm() -> int:
    from prahari.sim.farm import main as farm_main
    import asyncio
    asyncio.run(farm_main())
    return 0


def cmd_server() -> int:
    import uvicorn
    uvicorn.run("prahari.server.app:app", host="127.0.0.1", port=8000,
                log_level="warning")
    return 0


def cmd_scan(spec: Optional[str]) -> int:
    import asyncio
    import logging
    from prahari.cal.discovery import discover
    logging.basicConfig(level=logging.INFO, format="  %(message)s")
    spec = spec or _farm_scan_spec() or "127.0.0.0/24"
    print(f"\n  Scanning {spec}\n")
    rep = asyncio.run(discover(spec, max_channels=8))
    print(f"\n  {rep.hosts_scanned} endpoint(s) in {rep.elapsed_ms} ms "
          f"-> {len(rep.devices)} device(s), "
          f"{sum(len(d.channels) for d in rep.devices)} camera(s)\n")
    for d in rep.devices:
        print(f"  {d.ip}:{d.port}  {d.label or '?':10s} {d.model or '-':22s} "
              f"via={d.identified_by or 'none':9s} ch={d.channels}")
        for step in d.ladder:
            print(f"      rung {step.rung} {step.name:42s} "
                  f"{step.outcome:5s} {step.detail[:56]}")
    if not rep.devices:
        print("  Nothing found. Is the DVR farm running?  "
              "python -m prahari.run farm")
    return 0


def cmd_seed(days: int = 14) -> int:
    """Fast-forward a plausible fortnight of routine traffic per camera.

    A freshly installed system has no baseline, so it correctly refuses to
    dismiss anything and every event goes to a human. That is right in the
    field and useless in a five-minute demo. This writes the history a
    camera would really have accumulated after two weeks of ordinary
    daytime movement along its usual path -- and nothing else, so a 03:00
    crossing still reads as unprecedented.

    Synthetic, and labelled as such: it is a demo aid, not evidence.
    """
    # Seed through the running server, on the objects the workers already
    # hold. Writing the JSON from here would race the server's autosave and
    # be silently overwritten -- no restart needed either.
    got = _post(f"{SERVER_URL}/api/autonomy/seed", {"days": days}, timeout=120)
    if not got:
        print("  Could not reach the server. Start it first:"
              "  python -m prahari.run demo")
        return 1
    print(f"\n  Seeded {len(got.get('seeded', []))} camera baseline(s) with "
          f"{days} days of synthetic routine daytime traffic.\n")
    for sm in got.get("baselines", []):
        print(f"    {sm['camera_id']:22s} {sm['observations']:5d} obs  "
              f"span {sm['span_hours']:7.1f} h  mature={sm['mature']}")
    print("\n  Takes effect immediately -- no restart.\n")
    return 0


def _farm_scan_spec() -> Optional[str]:
    got = _get(f"{FARM_URL}/devices")
    return got.get("scan_spec") if got else None


def cmd_demo(scan: bool = True) -> int:
    media = os.path.join(ROOT, "media")
    if not any(f.endswith(".h264") for f in os.listdir(media)) \
            if os.path.isdir(media) else True:
        cmd_footage()

    print("\n  Starting Prahari\n")
    _spawn([PY, "-m", "prahari.sim.farm"], "farm")
    _spawn([PY, "-m", "prahari.tools.mock_c2", "--port", "9200"], "c2")
    _spawn([PY, "-m", "uvicorn", "prahari.server.app:app",
            "--host", "127.0.0.1", "--port", "8000",
            "--log-level", "warning"], "server")

    farm = _wait_for(f"{FARM_URL}/devices", "DVR farm")
    health = _wait_for(f"{SERVER_URL}/api/health", "server")
    if not farm or not health:
        print("\n  Startup failed. Check farm.log and server.log.\n")
        return 1

    mode = farm.get("mode", "?")
    spec = farm.get("scan_spec", "127.0.0.0/24")
    print(f"\n  DVR farm up in {mode.upper()} mode:")
    for d in farm.get("devices", []):
        print(f"    {d.get('key', d['ip']):22s} {d['manufacturer']:20s} "
              f"{d['model']:20s} {d['channels']} ch  "
              f"onvif={'on' if d['onvif'] else 'off'}")

    _post(f"{SERVER_URL}/api/northbound/webhook", {"url": C2_URL}, timeout=10)

    if scan:
        print(f"\n  Scanning {spec} …")
        got = _post(f"{SERVER_URL}/api/discover",
                    {"hosts": spec, "max_channels": 8})
        if got:
            rep = got["report"]
            print(f"    {rep['hosts_scanned']} endpoints -> "
                  f"{len(rep['devices'])} devices, {rep['cameras']} cameras "
                  f"in {rep['elapsed_ms']} ms")
            for d in rep["devices"]:
                print(f"      {d['ip']}:{d['port']:<5} {d['label'] or '?':10s} "
                      f"{d['model'] or '-':22s} via {d['identified_by']}")
            if rep["devices"]:
                _post(f"{SERVER_URL}/api/cameras/start", {"quality": "sub"},
                      timeout=120)
                print("    cameras connected")

    print(f"""
  Prahari is running.

    dashboard   {SERVER_URL}
    scan spec   {spec}
    logs        farm.log, server.log, c2.log  (in {ROOT})

  Press Ctrl-C to stop everything.
""")
    try:
        while True:
            time.sleep(1)
            for p, name in zip(_children, ("farm", "c2", "server")):
                if p.poll() is not None:
                    print(f"\n  ! {name} exited with code {p.returncode}; "
                          f"see {name}.log\n")
                    return 1
    except KeyboardInterrupt:
        print("\n  Stopping…")
    finally:
        _stop_all()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m prahari.run",
        description="Prahari launcher (works on Windows, macOS and Linux)")
    ap.add_argument("command",
                    choices=["demo", "farm", "server", "footage", "scan",
                             "seed-baseline"],
                    nargs="?", default="demo")
    ap.add_argument("--days", type=int, default=14,
                    help="'seed-baseline': how much synthetic history")
    ap.add_argument("--hosts", default=None,
                    help="target spec for 'scan' (default: ask the farm)")
    ap.add_argument("--no-scan", action="store_true",
                    help="'demo': start services but do not scan or connect")
    args = ap.parse_args(argv)

    os.chdir(ROOT)
    if args.command == "footage":
        return cmd_footage()
    if args.command == "farm":
        return cmd_farm()
    if args.command == "server":
        return cmd_server()
    if args.command == "scan":
        return cmd_scan(args.hosts)
    if args.command == "seed-baseline":
        return cmd_seed(args.days)
    return cmd_demo(scan=not args.no_scan)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _stop_all()
        sys.exit(130)
