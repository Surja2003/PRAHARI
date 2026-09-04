"""Alarm outputs — what happens when nobody is watching the screen.

An AUTO_ALARM that only turns a row amber in a browser is not an alarm. It
has to reach the physical world: a hooter on the outpost wall, a radio
call, a message to the section commander's phone, a priority flag into the
control room.

Also here: escalation. An alarm nobody acknowledges is not handled, so
after a timeout it goes up the chain, and keeps going. That loop is the
difference between an alerting system and a reporting system.

Every sink is best-effort and independent — a dead SMS gateway must never
stop the siren from sounding.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("prahari.server.alarm")


@dataclass
class AlarmSink:
    name: str
    enabled: bool = True
    fired: int = 0
    failed: int = 0

    def fire(self, alert: dict, decision: dict) -> bool:
        raise NotImplementedError


@dataclass
class RelaySink(AlarmSink):
    """The hooter on the wall.

    On an appliance this drives a GPIO line or a USB relay. Writing to a
    sysfs path keeps it dependency-free and testable: point it at a file
    and assert the file changed.
    """
    name: str = "siren-relay"
    path: str = field(default_factory=lambda: os.environ.get(
        "PRAHARI_RELAY_PATH", "state/siren.relay"))
    hold_s: float = 20.0
    _off_at: float = 0.0
    _timer: Optional[threading.Timer] = None

    def fire(self, alert: dict, decision: dict) -> bool:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w") as fh:
                fh.write("1\n")
            self._off_at = time.time() + self.hold_s
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self.hold_s, self._release)
            self._timer.daemon = True
            self._timer.start()
            self.fired += 1
            log.warning("SIREN ON (%s) %s", alert.get("camera_name"),
                        alert.get("message"))
            return True
        except OSError:
            self.failed += 1
            return False

    def _release(self):
        if time.time() < self._off_at - 0.5:
            return
        try:
            with open(self.path, "w") as fh:
                fh.write("0\n")
        except OSError:
            pass

    @property
    def active(self) -> bool:
        return time.time() < self._off_at


@dataclass
class NotifySink(AlarmSink):
    """SMS / radio dispatch / phone gateway, as a webhook."""
    name: str = "notify"
    url: str = ""
    timeout: float = 4.0
    recipients: List[str] = field(default_factory=list)

    def fire(self, alert: dict, decision: dict) -> bool:
        if not self.url:
            self.enabled = False
            return False
        body = json.dumps({
            "to": self.recipients,
            "priority": "high",
            "subject": f"PRAHARI ALARM · {alert.get('camera_name')}",
            "text": (f"{alert.get('message')}\n"
                     f"camera {alert.get('camera_name')} "
                     f"({alert.get('camera_id')})\n"
                     f"confidence {decision.get('score')} · "
                     f"{'; '.join(decision.get('reasons') or []) or 'rule match'}\n"
                     f"alert {alert.get('alert_uid')}"),
            "alert": alert,
            "decision": decision,
        }, default=str).encode()
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                r.read()
            self.fired += 1
            return True
        except Exception:                                     # noqa: BLE001
            self.failed += 1
            return False


class AlarmDispatcher:
    """Fans an alarm out to every sink, then watches for acknowledgement."""

    def __init__(self, sinks: Optional[List[AlarmSink]] = None,
                 escalate_after_s: float = 180.0,
                 on_escalate: Optional[Callable[[dict, int], None]] = None):
        self.sinks: List[AlarmSink] = sinks or []
        self.escalate_after_s = escalate_after_s
        self.on_escalate = on_escalate
        self._pending: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True,
                                        name="alarm-escalation")
        self._thread.start()
        self.escalations = 0

    def add(self, sink: AlarmSink) -> "AlarmDispatcher":
        self.sinks.append(sink)
        return self

    def fire(self, alert: dict, decision: dict) -> List[str]:
        fired = []
        for sink in self.sinks:
            if not sink.enabled:
                continue
            try:
                if sink.fire(alert, decision):
                    fired.append(sink.name)
            except Exception:                                 # noqa: BLE001
                log.exception("alarm sink %s failed", sink.name)
        uid = alert.get("alert_uid")
        if uid:
            with self._lock:
                self._pending[uid] = {"alert": alert, "decision": decision,
                                      "since": time.time(), "level": 0}
        return fired

    def acknowledge(self, alert_uid: str):
        with self._lock:
            self._pending.pop(alert_uid, None)

    def _watch(self):
        # Poll faster than the escalation window, or a short window never
        # fires at all.
        tick = max(0.25, min(5.0, self.escalate_after_s / 3.0))
        while not self._stop.wait(tick):
            now = time.time()
            due = []
            with self._lock:
                for uid, rec in list(self._pending.items()):
                    if now - rec["since"] >= self.escalate_after_s:
                        rec["level"] += 1
                        rec["since"] = now
                        due.append((uid, rec))
            for uid, rec in due:
                self.escalations += 1
                log.warning("ESCALATING unacknowledged alarm %s to level %d",
                            uid, rec["level"])
                for sink in self.sinks:
                    if sink.enabled:
                        try:
                            sink.fire(rec["alert"], rec["decision"])
                        except Exception:                     # noqa: BLE001
                            pass
                if self.on_escalate:
                    try:
                        self.on_escalate(rec["alert"], rec["level"])
                    except Exception:                         # noqa: BLE001
                        log.exception("escalation callback failed")

    def stop(self):
        self._stop.set()

    def status(self) -> dict:
        with self._lock:
            pending = len(self._pending)
        return {
            "sinks": [{"name": s.name, "enabled": s.enabled,
                       "fired": s.fired, "failed": s.failed}
                      for s in self.sinks],
            "unacknowledged": pending,
            "escalations": self.escalations,
            "siren_active": any(getattr(s, "active", False) for s in self.sinks),
        }
