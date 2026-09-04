"""Register the mock C2 as a northbound webhook consumer."""
from __future__ import annotations

import json
import sys
import urllib.request

SERVER = "http://127.0.0.1:8000"
C2 = "http://127.0.0.1:9200/events"


def main(server: str = SERVER, c2: str = C2) -> int:
    body = json.dumps({"url": c2}).encode()
    req = urllib.request.Request(
        f"{server}/api/northbound/webhook", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            out = json.loads(resp.read())
        print(f"  northbound consumers: {out.get('emitters')}")
        return 0
    except Exception as exc:                                  # noqa: BLE001
        print(f"  could not register mock C2 ({exc})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
