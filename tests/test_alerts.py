"""Deterministic tests for the suppression layer.

The end-to-end run exercises deduplication only if the footage happens to
produce duplicates, which is not a test -- it is a coincidence. These drive
the AlertManager directly so each suppression mechanism is proved on
purpose: dedup, cooldown expiry, storm protection, incident joining, and
the tamper-evidence of the audit chain.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

from prahari.perception.rules import RuleEvent, Severity
from prahari.server.alerts import AlertManager, State
from prahari.server.store import Store

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append(bool(ok))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail else ""))


def event(ts: float, track_id: int = 7, camera: str = "cam-1",
          rule: str = "fence-1", label: str = "person") -> RuleEvent:
    return RuleEvent(rule_id=rule, rule_type="tripwire", camera_id=camera,
                     track_id=track_id, label=label,
                     severity=Severity.HIGH, message="person crossed fence",
                     ts=ts, box=(10.0, 20.0, 40.0, 90.0),
                     direction="a_to_b")


def main() -> int:
    print("\n  Alert suppression — deterministic checks\n  " + "-" * 58)
    tmp = tempfile.mkdtemp(prefix="prahari-test-")
    store = Store(os.path.join(tmp, "test.db"))
    mgr = AlertManager(store, cooldown_s=25.0, storm_threshold=5,
                       storm_window_s=60.0, storm_mute_s=120.0)

    # -- counters are complete even when untouched ----------------------
    m = mgr.metrics()
    check("metrics report zero, never null",
          m.get("deduped") == 0 and m.get("raised") == 0,
          "a dashboard reading these gets numbers")

    # -- one track crossing one line is ONE alert -----------------------
    t0 = time.time()
    first = mgr.handle(event(t0), {"camera_name": "BOP-7"})
    check("first crossing raises an alert", first is not None)

    folded = [mgr.handle(event(t0 + i * 0.5), {"camera_name": "BOP-7"})
              for i in range(1, 11)]
    check("same track re-firing is folded, not re-raised",
          all(f is None for f in folded), "10 repeats absorbed")

    stored = store.alert(first["alert_uid"])
    check("folded repeats increment the occurrence count",
          stored["occurrences"] == 11, f"occurrences={stored['occurrences']}")
    check("only one row exists for the crossing",
          len(store.alerts(limit=50)) == 1)

    m = mgr.metrics()
    check("dedup ratio reported",
          m["deduped"] == 10 and m["raised"] == 1,
          f"{int(m['dedup_ratio'] * 100)}% of events suppressed")

    # -- a genuinely new crossing must still get through ----------------
    second = mgr.handle(event(t0 + 1, track_id=8), {"camera_name": "BOP-7"})
    check("a different track is a different alert", second is not None)

    later = mgr.handle(event(t0 + 40, track_id=7), {"camera_name": "BOP-7"})
    check("the same track after the cooldown re-alerts", later is not None,
          "a real second crossing is not lost")

    # -- storm protection ----------------------------------------------
    print()
    storm_mgr = AlertManager(Store(os.path.join(tmp, "storm.db")),
                            cooldown_s=0.0, storm_threshold=5,
                            storm_window_s=60.0, storm_mute_s=120.0)
    t1 = time.time()
    raised = [storm_mgr.handle(event(t1 + i, track_id=100 + i,
                                     camera="cam-storm"))
              for i in range(30)]
    got = sum(1 for r in raised if r is not None)
    check("storm does not produce a row per event", got < 10,
          f"{got} rows from 30 events (a spider on the lens)")
    rows = storm_mgr.store.alerts(limit=100)
    storms = [r for r in rows if r["rule_type"] == "alert_storm"]
    check("one meta-alert raised instead", len(storms) == 1,
          storms[0]["message"][:64] + "…" if storms else "none")
    check("camera muted after the storm",
          "cam-storm" in storm_mgr.metrics()["muted_cameras"])

    # -- cross-camera incident joining ----------------------------------
    print()
    inc_mgr = AlertManager(Store(os.path.join(tmp, "inc.db")),
                           cooldown_s=25.0, storm_threshold=999,
                           incident_window_s=30.0)
    t2 = time.time()
    a = inc_mgr.handle(event(t2, track_id=1, camera="cam-a"))
    b = inc_mgr.handle(event(t2 + 3, track_id=2, camera="cam-b"))
    c = inc_mgr.handle(event(t2 + 6, track_id=3, camera="cam-c"))
    ids = {x["attributes"]["incident_id"] for x in (a, b, c) if x}
    check("one intruder across three cameras is one incident",
          len(ids) == 1, f"incident {list(ids)[0][:8]}… spans 3 views")

    # -- lifecycle and active learning ----------------------------------
    print()
    uid = first["alert_uid"]
    mgr.acknowledge(uid, "havildar.singh")
    check("acknowledge records the operator",
          store.alert(uid)["acknowledged_by"] == "havildar.singh")
    mgr.adjudicate(uid, "false", "havildar.singh", "cattle")
    got = store.alert(uid)
    check("adjudication closes the alert",
          got["state"] == State.ADJUDICATED and got["adjudication"] == "false")
    labels = store.labels()
    check("a dismissal becomes a training label",
          len(labels) == 1 and labels[0]["verdict"] == "false",
          "the active-learning loop, closed by an operator")

    # -- audit chain -----------------------------------------------------
    print()
    check("audit chain verifies", store.verify_audit()["valid"] is True,
          f"{store.verify_audit()['entries']} entries")

    # tamper with one row and prove the chain notices
    conn = store._conn()                                      # noqa: SLF001
    with store._lock:                                         # noqa: SLF001
        conn.execute("UPDATE audit SET detail = ? WHERE id = "
                     "(SELECT MIN(id) FROM audit)", ('{"tampered":true}',))
        conn.commit()
    verdict = store.verify_audit()
    check("edited audit row is detected", verdict["valid"] is False,
          f"chain breaks at entry {verdict.get('broken_at')}")

    ok = sum(1 for r in results if r)
    print("\n  " + "-" * 58)
    print(f"  {ok}/{len(results)} checks passed\n")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
