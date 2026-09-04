"""A stand-in command-and-control system.

Run this beside the demo and point Prahari's webhook at it. It prints each
alert exactly as a third-party C2 receives it: the ONVIF Profile M Scene
Description, the ONVIF Events notification, and the CEF line a SIEM would
ingest.

The point it makes in front of a judge: none of this is a Prahari-specific
format. Any Profile M consumer -- Milestone XProtect, Genetec, Axis, Bosch,
Hanwha -- takes the same bytes with no adapter written for us.

    python -m prahari.tools.mock_c2 --port 9200
    curl -XPOST localhost:8000/api/northbound/webhook \
         -d '{"url":"http://127.0.0.1:9200/events"}' \
         -H 'Content-Type: application/json'
"""
from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
AMBER = "\033[33m"
RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"

SEV_COLOUR = {"info": DIM, "low": CYAN, "medium": AMBER,
              "high": AMBER + BOLD, "critical": RED + BOLD}

STATE = {"count": 0, "verbose": False}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):        # silence the default access log
        pass

    def do_POST(self):                                        # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"received":true}')
        self._render(payload)

    def _render(self, payload: dict):
        STATE["count"] += 1
        alert = payload.get("alert", {})
        pm = payload.get("profileM", {})
        sev = str(alert.get("severity", "info"))
        colour = SEV_COLOUR.get(sev, "")
        stamp = time.strftime("%H:%M:%S",
                              time.localtime(alert.get("ts", time.time())))

        print(f"\n{colour}{'=' * 76}{RESET}")
        print(f"{colour}[{STATE['count']:03d}] {stamp}  {sev.upper():8s} "
              f"{alert.get('message', '')}{RESET}")
        print(f"{DIM}      camera={alert.get('camera_name')} "
              f"({alert.get('camera_id')})  rule={alert.get('rule_id')}  "
              f"track={alert.get('track_id')}  uid={alert.get('alert_uid')}{RESET}")

        print(f"\n{GREEN}  -- ONVIF Profile M (JSON binding) "
              f"-------------------------{RESET}")
        print(f"     class={pm.get('class')}  objectId={pm.get('objectId')}  "
              f"box={pm.get('boundingBox')}")
        if pm.get("geoLocation"):
            print(f"     geoLocation={pm.get('geoLocation')}")
        if alert.get("evidence_sha"):
            print(f"     evidenceSha256={alert['evidence_sha'][:32]}...")

        print(f"\n{GREEN}  -- ONVIF Scene Description (RTP metadata payload) "
              f"------{RESET}")
        xml = payload.get("sceneDescriptionXml", "")
        print("     " + (xml if STATE["verbose"] else xml[:300] +
                         ("..." if len(xml) > 300 else "")))

        print(f"\n{GREEN}  -- ONVIF Events topic "
              f"-------------------------------------{RESET}")
        ev = payload.get("onvifNotificationXml", "")
        topic = ""
        if "<wsnt:Topic" in ev:
            topic = ev.split("</wsnt:Topic>")[0].split(">")[-1]
        print(f"     {topic or '(none)'}")

        print(f"\n{GREEN}  -- CEF for SIEM "
              f"-------------------------------------------{RESET}")
        print(f"     {payload.get('cef','')[:200]}")
        print(f"{colour}{'=' * 76}{RESET}", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Mock C2 / VMS consumer")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--verbose", action="store_true",
                    help="print the full Scene Description XML")
    args = ap.parse_args()
    STATE["verbose"] = args.verbose

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"\n  Mock command-and-control listening on "
          f"http://{args.host}:{args.port}/events")
    print("  Register it with Prahari:")
    print(f"    curl -XPOST localhost:8000/api/northbound/webhook \\\n"
          f"         -H 'Content-Type: application/json' \\\n"
          f"         -d '{{\"url\":\"http://{args.host}:{args.port}/events\"}}'\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  {STATE['count']} alert(s) received.\n")


if __name__ == "__main__":
    main()
