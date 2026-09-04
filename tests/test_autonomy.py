"""Does the system actually decide for itself?

The claim being tested is operational, not statistical: with nobody sitting
in front of the screen, routine traffic must stop reaching a person, a
genuine 03:00 intrusion must still sound a siren, and nothing dangerous
must ever be quietly filed away.

Each check below is one of those sentences.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

from prahari.perception.normality import NormalityModel, NormalityStore
from prahari.server.alarm import AlarmDispatcher, RelaySink
from prahari.server.autonomy import AutonomyEngine, AutonomyPolicy, Band

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  — {detail}" if detail else ""))


def at(day: int, hour: int, minute: int = 0) -> float:
    """A timestamp at a given weekday/hour in local time."""
    base = time.localtime(time.time())
    lt = list(base)
    lt[3], lt[4], lt[5] = hour, minute, 0
    ts = time.mktime(tuple(lt))
    # walk back to the requested weekday
    while time.localtime(ts).tm_wday != day:
        ts -= 86400
    return ts


FRAME = (1280, 720)


def teach_routine(m: NormalityModel, days: int = 14):
    """Three weeks of ordinary daytime traffic along one path."""
    for d in range(days):
        for wd in range(7):
            for hour in (8, 9, 10, 12, 15, 17):
                for k in range(3):
                    m.observe(ts=at(wd, hour, k * 7) - d * 604800,
                              label="person",
                              foot_xy=(560 + k * 12, 520),
                              frame_wh=FRAME, height_px=90,
                              speed_px_s=48 + k, dwell_s=6 + k)


def main() -> int:
    print("\n  Autonomy — deciding without a person\n  " + "-" * 58)

    # ---------------------------------------------------------------
    # 1. the baseline learns unsupervised
    # ---------------------------------------------------------------
    m = NormalityModel("cam-1")
    check("a fresh camera knows nothing", not m.mature,
          "nothing may be dismissed yet")
    teach_routine(m)
    check("baseline matures from ordinary traffic alone", m.mature,
          f"{m.observations} tracks over {m.span_hours/24:.0f} days, no labels")

    routine = m.score(ts=at(2, 9, 20), label="person", foot_xy=(566, 520),
                      frame_wh=FRAME, height_px=90, speed_px_s=50, dwell_s=7)
    intruder = m.score(ts=at(2, 3, 12), label="person", foot_xy=(180, 300),
                       frame_wh=FRAME, height_px=90, speed_px_s=50, dwell_s=7)
    check("routine movement scores near zero", routine.score < 0.25,
          f"09:20 on the usual path → {routine.score:.2f}")
    check("same person, 03:12, off-path scores high", intruder.score > 0.55,
          f"→ {intruder.score:.2f}: {'; '.join(intruder.reasons[:2])}")
    check("the score is explainable", len(intruder.reasons) >= 1,
          "; ".join(intruder.reasons))

    # night-but-normal-place should still beat day-and-normal
    night_path = m.score(ts=at(2, 3, 12), label="person", foot_xy=(566, 520),
                         frame_wh=FRAME, height_px=90, speed_px_s=50,
                         dwell_s=7)
    check("time and place contribute independently",
          routine.score < night_path.score < intruder.score,
          f"{routine.score:.2f} < {night_path.score:.2f} < {intruder.score:.2f}")

    # ---------------------------------------------------------------
    # 2. baselines survive a reboot
    # ---------------------------------------------------------------
    print()
    tmp = tempfile.mkdtemp(prefix="prahari-auto-")
    path = os.path.join(tmp, "normality.json")
    st = NormalityStore(path, autosave_s=0)
    st.models["cam-1"] = m
    st.save(force=True)
    again = NormalityStore(path)
    reloaded = again.get("cam-1")
    check("baseline persists across restart", reloaded.mature,
          f"{reloaded.observations} observations restored — an outpost that "
          f"loses power weekly would otherwise never mature")

    # ---------------------------------------------------------------
    # 3. the decision bands
    # ---------------------------------------------------------------
    print()
    eng = AutonomyEngine(AutonomyPolicy(alarm_threshold=0.62,
                                        review_threshold=0.30))
    solid = {"hits": 30, "score": 0.9, "class_stability": 1.0}

    routine_alert = {
        "ts": at(2, 9, 20), "camera_id": "cam-1", "track_id": 1,
        "rule_id": "fence-1", "rule_type": "tripwire", "severity": "medium",
        "attributes": {"night": False, "zone_criticality": "normal"}}
    d_routine = eng.decide(routine_alert, anomaly=routine.as_dict(),
                           track_quality=solid)
    check("routine daytime crossing is handled without a person",
          d_routine.band is Band.AUTO_LOG,
          f"score {d_routine.score:.2f} → logged, nobody paged")

    night_alert = {
        "ts": at(2, 3, 12), "camera_id": "cam-1", "track_id": 2,
        "rule_id": "fence-1", "rule_type": "tripwire", "severity": "high",
        "attributes": {"night": True, "zone_criticality": "normal"}}
    d_night = eng.decide(night_alert, anomaly=intruder.as_dict(),
                         track_quality=solid)
    check("03:12 off-path crossing raises the alarm by itself",
          d_night.band is Band.AUTO_ALARM and d_night.alarm,
          f"score {d_night.score:.2f} → siren, no human in the loop")
    check("the alarm carries its reasoning",
          len(d_night.reasons) > 0, "; ".join(d_night.reasons[:3]))

    # ---------------------------------------------------------------
    # 4. fail-safe: it must never be quietly wrong
    # ---------------------------------------------------------------
    print()
    eng2 = AutonomyEngine(AutonomyPolicy())
    tamper = eng2.decide({"ts": time.time(), "camera_id": "cam-9",
                          "track_id": -1, "rule_id": "tamper",
                          "rule_type": "tamper", "severity": "critical",
                          "attributes": {}},
                         anomaly={}, track_quality={})
    check("camera tamper can never be silenced",
          tamper.band is Band.AUTO_ALARM,
          "; ".join(tamper.overrides))

    weak = {"hits": 4, "score": 0.3, "class_stability": 0.5}
    crit = eng2.decide({"ts": at(2, 9), "camera_id": "cam-2", "track_id": 5,
                        "rule_id": "z", "rule_type": "zone_entry",
                        "severity": "low",
                        "attributes": {"zone_criticality": "critical"}},
                       anomaly=routine.as_dict(), track_quality=weak)
    check("a critical zone is never auto-logged",
          crit.band is not Band.AUTO_LOG, "; ".join(crit.overrides))

    eng3 = AutonomyEngine(AutonomyPolicy())
    immature = eng3.decide({"ts": at(2, 9), "camera_id": "cam-new",
                            "track_id": 1, "rule_id": "f",
                            "rule_type": "tripwire", "severity": "low",
                            "attributes": {}},
                           anomaly={"score": 0.0, "mature": False},
                           track_quality=weak)
    check("a camera that has not learned yet dismisses nothing",
          immature.band is not Band.AUTO_LOG,
          "stays supervised until its baseline matures")

    eng4 = AutonomyEngine(AutonomyPolicy())
    anpr = eng4.decide({"ts": at(2, 3), "camera_id": "cam-far", "track_id": 3,
                        "rule_id": "anpr", "rule_type": "anpr",
                        "severity": "critical",
                        "attributes": {"night": True}},
                       anomaly=intruder.as_dict(), track_quality=solid,
                       capability_ok=False)
    check("a claim the optics cannot support is downgraded, not trusted",
          anpr.band is not Band.AUTO_ALARM, "; ".join(anpr.overrides))

    # ---------------------------------------------------------------
    # 5. corroboration lifts a weak single source
    # ---------------------------------------------------------------
    print()
    eng5 = AutonomyEngine(AutonomyPolicy())
    now = time.time()
    base = {"ts": now, "camera_id": "cam-a", "track_id": 1, "rule_id": "f1",
            "rule_type": "tripwire", "severity": "medium", "attributes": {}}
    alone = eng5.decide(dict(base), anomaly=intruder.as_dict(),
                        track_quality=solid)
    eng5.decide({**base, "camera_id": "cam-b", "track_id": 2},
                anomaly=intruder.as_dict(), track_quality=solid)
    together = eng5.decide({**base, "camera_id": "cam-c", "track_id": 3,
                            "ts": now + 3},
                           anomaly=intruder.as_dict(), track_quality=solid)
    check("agreement between UNUSUAL sightings raises the score",
          together.score > alone.score,
          f"{alone.score:.2f} alone → {together.score:.2f} corroborated")

    eng7 = AutonomyEngine(AutonomyPolicy())
    r_alone = eng7.decide(dict(base), anomaly=routine.as_dict(),
                          track_quality=solid)
    for i in range(4):
        eng7.decide({**base, "camera_id": f"cam-r{i}", "track_id": 10 + i},
                    anomaly=routine.as_dict(), track_quality=solid)
    r_many = eng7.decide({**base, "camera_id": "cam-r9", "track_id": 20},
                         anomaly=routine.as_dict(), track_quality=solid)
    check("simultaneous ROUTINE sightings are a timetable, not evidence",
          r_many.score < alone.score and r_many.band is not Band.AUTO_ALARM,
          f"5 cameras agreeing on routine → {r_many.score:.2f}, still no alarm")

    # ---------------------------------------------------------------
    # 6. the number that answers the objection
    # ---------------------------------------------------------------
    print()
    eng6 = AutonomyEngine(AutonomyPolicy())
    for i in range(400):
        eng6.decide({"ts": at(i % 7, 9, i % 60), "camera_id": f"cam-{i%9}",
                     "track_id": i, "rule_id": "fence", "rule_type": "tripwire",
                     "severity": "medium",
                     "attributes": {"night": False}},
                    anomaly=routine.as_dict(), track_quality=solid)
    mm = eng6.metrics()
    check("routine traffic does not reach an operator",
          mm["review"] + mm["auto_alarm"] < mm["total"] * 0.15,
          f"{mm['total']} events → {mm['review']} for review, "
          f"{mm['auto_alarm']} alarms "
          f"({int(mm['autonomy_ratio']*100)}% handled autonomously)")

    # ---------------------------------------------------------------
    # 7. the siren actually fires
    # ---------------------------------------------------------------
    print()
    relay = os.path.join(tmp, "siren.relay")
    disp = AlarmDispatcher(sinks=[RelaySink(path=relay, hold_s=1.0)],
                           escalate_after_s=1.0)
    fired = disp.fire({"alert_uid": "a1", "camera_name": "BOP-7",
                       "camera_id": "cam-1", "message": "intrusion"},
                      d_night.as_dict())
    check("alarm reaches a physical output", "siren-relay" in fired,
          f"{relay} = {open(relay).read().strip()}")
    time.sleep(2.5)
    check("an unacknowledged alarm escalates on its own",
          disp.escalations >= 1, f"{disp.escalations} escalation(s)")
    disp.acknowledge("a1")
    time.sleep(1.5)
    before = disp.escalations
    time.sleep(1.5)
    check("acknowledging stops the escalation", disp.escalations == before)
    disp.stop()

    ok = sum(1 for r in results if r)
    print("\n  " + "-" * 58)
    print(f"  {ok}/{len(results)} checks passed\n")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
