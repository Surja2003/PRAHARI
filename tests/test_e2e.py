"""End-to-end verification of the Phase 0 thin slice.

Exercises the whole path the demo depends on, against the running stack:

    scan -> identify brands -> connect -> detect -> track -> rule fires
         -> cascade -> dedup -> stored alert -> ONVIF Profile M northbound
         -> link degradation -> recovery
         -> audit chain integrity

Run with the farm, server and mock C2 up:  make demo && make test
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

SERVER = "http://127.0.0.1:8000"
FARM = "http://127.0.0.1:9099"

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail else ""))
    return ok


def get(path: str, base: str = SERVER):
    with urllib.request.urlopen(base + path, timeout=120) as r:
        return json.loads(r.read())


def post(path: str, payload: dict | None = None, base: str = SERVER):
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        base + path, data=data, method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read())


def main() -> int:
    print("\n  Prahari end-to-end verification\n" + "  " + "-" * 60)

    # -- 1. health ------------------------------------------------------
    try:
        h = get("/api/health")
        check("server reachable", bool(h.get("ok")), f"detector={h.get('detector')}")
    except Exception as exc:                                  # noqa: BLE001
        check("server reachable", False, str(exc))
        print("\n  Start the stack first:  make demo\n")
        return 1

    # -- 2. discovery ---------------------------------------------------
    print("\n  Discovery ladder")
    # Ask the farm where it is listening: alias mode on Linux, port mode on
    # any OS that routes only 127.0.0.1 to loopback (Windows, macOS).
    farm = get("/api/link")
    spec = farm.get("scan_spec") or "127.0.0.0/24"
    mode = farm.get("mode", "alias")
    print(f"  simulator mode: {mode}  |  scanning {spec}")
    r = post("/api/discover", {"hosts": spec, "max_channels": 8})
    rep = r["report"]
    devices = rep["devices"]
    check("targets scanned",
          rep["hosts_scanned"] >= (254 if mode == "alias" else 4),
          f"{rep['hosts_scanned']} endpoints in {rep['elapsed_ms']} ms")
    check("four DVRs found", len(devices) == 4, f"{len(devices)} found")
    check("cameras enumerated", rep["cameras"] >= 8,
          f"{rep['cameras']} cameras")

    # Address the devices by their position in the farm, which is stable in
    # both modes: [hikvision, cpplus, uniview, axis].
    order = sorted(devices, key=lambda d: (d["ip"], d["port"]))
    keys = [f"{d['ip']}:{d['port']}" for d in order]
    labels = [d["label"] for d in order]
    methods = [d["identified_by"] for d in order]

    check("Hikvision identified", labels[0] == "Hikvision", keys[0])
    if mode == "alias":
        check("CP Plus identified (not mistaken for Dahua)",
              labels[1] == "CP Plus",
              "OEM rebrand resolved from the login-page banner")
    else:
        check("CP Plus resolved to the Dahua family",
              labels[1] in ("CP Plus", "Dahua"),
              "OEM badge lives only on the web UI, which cannot be "
              "attributed when four DVRs share one address")
    check("Uniview identified", labels[2] == "Uniview", keys[2])
    check("Axis identified", labels[3] == "Axis", keys[3])

    check("ONVIF fast path used where enabled",
          methods[2] == "onvif" and methods[3] == "onvif")
    check("template fallback used where ONVIF is off",
          methods[0] == "template" and methods[1] == "template",
          "the rungs that matter on real field hardware")

    hik = order[0]
    check("channel enumeration walked the DVR",
          len(hik["channels"]) == 4, f"{len(hik['channels'])} analog channels")
    subs = [s for s in hik["streams"] if s["which"] == "sub"]
    check("main and sub streams distinguished",
          all(s["width"] < 900 for s in subs), f"{len(subs)} substreams")

    # -- 3. connect and run --------------------------------------------
    print("\n  Perception")
    post("/api/cameras/start", {"quality": "sub"})
    running = connected = []
    # Nine simultaneous RTSP connections on a 2-core box do not all come up
    # at once; poll rather than assume a fixed settle time.
    for _ in range(20):
        time.sleep(2)
        cams = get("/api/cameras")["cameras"]
        running = [c for c in cams if c.get("running")]
        connected = [c for c in running
                     if (c.get("status") or {}).get("connected")]
        if len(connected) >= 8:
            break
    check("cameras connected", len(running) >= 8, f"{len(running)} running")
    check("streams decoding", len(connected) >= 8,
          f"{len(connected)}/{len(running)} pulling frames")

    print("\n  Waiting 40s for tracks, rules and alerts…")
    time.sleep(40)

    cams = get("/api/cameras")["cameras"]
    roles = {}
    for c in cams:
        st = c.get("status") or {}
        roles[st.get("role", "unknown")] = roles.get(st.get("role", "unknown"), 0) + 1
    check("camera roles profiled automatically",
          roles.get("perimeter", 0) + roles.get("approach", 0)
          + roles.get("chokepoint", 0) > 0, str(roles))

    # Pick the camera that actually sees the least, not just any camera
    # tagged perimeter: a wide view can still resolve a plate when a
    # vehicle drives right up to it, and gating is about what a view can
    # resolve, not about its label.
    scaled = [c for c in cams
              if ((c.get("status") or {}).get("optics") or {}).get(
                  "median_person_px")]
    perim = sorted(scaled, key=lambda c: c["status"]["optics"]
                   ["median_person_px"])
    if perim:
        caps = (perim[0].get("status") or {}).get("capabilities", {})
        px = perim[0]["status"]["optics"]["median_person_px"]
        print(f"  furthest view: {perim[0]['camera_id']} "
              f"(people {px:.0f} px tall)")
        check("ANPR gated off on a perimeter view", caps.get("anpr") is False,
              "plates do not resolve at this scale — capability greyed out")
        check("face matching gated off", caps.get("face_match") is False,
              "needs ~40 px eye spacing; physically unavailable here")
        check("human detection and fence enabled",
              caps.get("human_detect") and caps.get("virtual_fence"))

    # -- 4. alerts ------------------------------------------------------
    print("\n  Alerts and suppression")
    m = get("/api/metrics")
    a = m["alerts"]
    check("rule events generated", m["rule_events"] > 0,
          f"{m['rule_events']} events")
    check("alerts raised", a.get("raised", 0) > 0, f"{a.get('raised')} raised")
    # Whether the live footage happens to produce duplicates is incidental;
    # tests/test_alerts.py proves the mechanism deterministically. Here we
    # only assert the counters are wired and reporting numbers.
    check("suppression counters wired",
          isinstance(a.get("deduped"), int) and isinstance(a.get("raised"), int),
          f"{a.get('deduped')} folded, {a.get('raised')} raised "
          f"({int(a.get('dedup_ratio', 0) * 100)}% reduction) — "
          f"mechanism proved in tests/test_alerts.py")

    alerts = get("/api/alerts?limit=50")["alerts"]
    check("alerts persisted", len(alerts) > 0, f"{len(alerts)} stored")
    if alerts:
        first = alerts[0]
        check("evidence clip written", bool(first.get("evidence_clip")))
        check("evidence hashed for chain of custody",
              bool(first.get("evidence_sha")),
              (first.get("evidence_sha") or "")[:16] + "…")
        check("model version stamped on the alert",
              bool(first.get("model_version")), first.get("model_version"))

        # -- 5. northbound ---------------------------------------------
        print("\n  Northbound (capability 09)")
        uid = first["alert_uid"]
        with urllib.request.urlopen(
                f"{SERVER}/api/northbound/profile-m/{uid}.xml", timeout=10) as r2:
            xml = r2.read().decode()
        check("ONVIF Scene Description emitted",
              "tt:MetadataStream" in xml and "BoundingBox" in xml)
        check("Profile M object class mapped",
              any(c in xml for c in ("Human", "Vehicle", "Animal", "Other")))
        with urllib.request.urlopen(
                f"{SERVER}/api/northbound/onvif-event/{uid}.xml", timeout=10) as r2:
            ev = r2.read().decode()
        check("ONVIF Events topic emitted", "tns1:RuleEngine" in ev
              or "tns1:VideoSource" in ev)
        with urllib.request.urlopen(
                f"{SERVER}/api/northbound/cef/{uid}", timeout=10) as r2:
            cefline = r2.read().decode()
        check("CEF line for SIEM", cefline.startswith("CEF:0|Prahari"))

        nb = m.get("northbound") or []
        delivered = sum(e.get("sent", 0) for e in nb)
        check("C2 consumer actually received alerts", delivered > 0,
              f"{delivered} delivered to the mock C2")

        # -- 6. lifecycle ----------------------------------------------
        print("\n  Alert lifecycle and active learning")
        post(f"/api/alerts/{uid}/ack")
        got = get(f"/api/alerts/{uid}")
        check("alert acknowledged", got["state"] == "acknowledged")
        post(f"/api/alerts/{uid}/adjudicate",
             {"verdict": "false", "actor": "tester", "note": "e2e"})
        got = get(f"/api/alerts/{uid}")
        check("alert adjudicated", got["state"] == "adjudicated")
        labels = get("/api/labels")["labels"]
        check("dismissal queued for active learning", len(labels) > 0,
              "operator labelled training data without knowing it")

    # -- 7. link degradation -------------------------------------------
    print("\n  Link degradation and recovery")
    before = get("/api/metrics")["cameras"]
    fps_before = sum(c["fps"] for c in before) / max(len(before), 1)
    post("/api/link", {"preset": "lte"})
    time.sleep(12)
    mid = get("/api/metrics")["cameras"]
    still = [c for c in mid if c["connected"]]
    check("survives a 4G-grade link", len(still) >= len(mid) * 0.7,
          f"{len(still)}/{len(mid)} cameras still detecting locally")

    post("/api/link", {"preset": "down"})
    time.sleep(14)
    post("/api/link", {"preset": "fibre"})
    time.sleep(16)
    after = get("/api/metrics")["cameras"]
    recovered = [c for c in after if c["connected"]]
    check("recovers after a full outage", len(recovered) >= len(after) * 0.7,
          f"{len(recovered)}/{len(after)} reconnected without intervention")
    fps_after = sum(c["fps"] for c in after) / max(len(after), 1)
    check("throughput restored", fps_after > 1.0,
          f"{fps_before:.1f} fps before, {fps_after:.1f} fps after")

    # -- 8. audit -------------------------------------------------------
    print("\n  Evidentiary integrity")
    chain = get("/api/audit/verify")
    check("hash-chained audit log verifies", chain.get("valid") is True,
          f"{chain.get('entries')} entries, head "
          f"{(chain.get('head') or '')[:16]}…")

    # -- summary --------------------------------------------------------
    ok = sum(1 for r in results if r)
    print("\n  " + "-" * 60)
    print(f"  {ok}/{len(results)} checks passed\n")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
