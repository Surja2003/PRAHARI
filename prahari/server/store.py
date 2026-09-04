"""Event store and tamper-evident audit log (PS capability 08).

SQLite here so the demo runs with nothing installed; the schema is written
to move to PostgreSQL + TimescaleDB unchanged, where alerts become a
hypertable and "alerts per BOP per hour over 30 days" is one fast query.

Two things are not optional even in a prototype, because an alert can end
up justifying a detention:

  model_version on every event   when you retrain, you must still be able
                                 to explain an alert raised six months ago
  hash-chained audit log         each entry carries the SHA-256 of the one
                                 before it, so any later edit is detectable
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uid     TEXT UNIQUE NOT NULL,
    ts            REAL NOT NULL,
    camera_id     TEXT NOT NULL,
    camera_name   TEXT,
    bop           TEXT,
    rule_id       TEXT,
    rule_type     TEXT,
    label         TEXT,
    track_id      INTEGER,
    severity      TEXT,
    state         TEXT NOT NULL DEFAULT 'raised',
    message       TEXT,
    direction     TEXT,
    dwell_s       REAL,
    speed_kmh     REAL,
    ground_x      REAL,
    ground_y      REAL,
    box           TEXT,
    attributes    TEXT,
    evidence_clip TEXT,
    thumbnail     TEXT,
    evidence_sha  TEXT,
    model_version TEXT,
    detector      TEXT,
    band          TEXT NOT NULL DEFAULT 'review',
    decision_score REAL,
    anomaly_score REAL,
    decision      TEXT,
    occurrences   INTEGER NOT NULL DEFAULT 1,
    last_ts       REAL,
    acknowledged_by TEXT,
    acknowledged_ts REAL,
    adjudication  TEXT,
    closed_ts     REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_cam ON alerts(camera_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);
CREATE INDEX IF NOT EXISTS idx_alerts_band ON alerts(band, ts DESC);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT,
    detail    TEXT,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);

CREATE TABLE IF NOT EXISTS cameras (
    camera_id   TEXT PRIMARY KEY,
    name        TEXT,
    device_ip   TEXT,
    brand       TEXT,
    model       TEXT,
    channel     INTEGER,
    url_main    TEXT,
    url_sub     TEXT,
    role        TEXT,
    capabilities TEXT,
    optics      TEXT,
    bop         TEXT,
    lat         REAL,
    lon         REAL,
    updated_ts  REAL
);

CREATE TABLE IF NOT EXISTS labels (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    alert_uid TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    actor     TEXT,
    note      TEXT
);
"""

GENESIS = "0" * 64


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class Store:
    def __init__(self, path: str = "prahari.db"):
        self.path = path
        self._local = threading.local()
        self._lock = threading.Lock()
        self.recovered_from: Optional[str] = None
        try:
            with self._conn() as c:
                c.executescript(SCHEMA)
        except sqlite3.DatabaseError as exc:
            # A border outpost loses power mid-write and nobody is there to
            # run a repair. A damaged or half-truncated database must never
            # stop the appliance from coming back up watching: set the old
            # file aside (it is evidence, so it is kept, not deleted) and
            # start a clean one.
            self.recovered_from = self._quarantine(exc)
            with self._conn() as c:
                c.executescript(SCHEMA)
            self.audit("system", "store.recovered", self.path,
                       {"reason": str(exc), "kept_as": self.recovered_from})

    def _quarantine(self, exc: Exception) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        moved = []
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None
        for suffix in ("", "-wal", "-shm"):
            src = self.path + suffix
            if not os.path.exists(src):
                continue
            dst = f"{self.path}.broken-{stamp}{suffix}"
            try:
                os.replace(src, dst)
                moved.append(dst)
            except OSError:
                # Some mounts refuse rename and unlink alike; truncating at
                # least gives SQLite a clean page to start from.
                try:
                    with open(src, "wb"):
                        pass
                except OSError:
                    pass
        return moved[0] if moved else f"{self.path} (truncated in place)"

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=15,
                                   check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------
    def insert_alert(self, row: Dict[str, Any]) -> int:
        cols = [k for k in row if k != "id"]
        sql = (f"INSERT OR IGNORE INTO alerts ({','.join(cols)}) "
               f"VALUES ({','.join('?' * len(cols))})")
        with self._lock, self._conn() as c:
            cur = c.execute(sql, [row[k] for k in cols])
            return cur.lastrowid

    def bump_alert(self, alert_uid: str, ts: float) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE alerts SET occurrences = occurrences + 1, "
                      "last_ts = ? WHERE alert_uid = ?", (ts, alert_uid))

    def update_alert(self, alert_uid: str, **fields) -> None:
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self._lock, self._conn() as c:
            c.execute(f"UPDATE alerts SET {sets} WHERE alert_uid = ?",
                      [*fields.values(), alert_uid])

    def alerts(self, limit: int = 100, camera_id: Optional[str] = None,
               state: Optional[str] = None, since: Optional[float] = None,
               band: Optional[str] = None, needs_human: bool = False
               ) -> List[dict]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: List[Any] = []
        if band:
            sql += " AND band = ?"
            args.append(band)
        if needs_human:
            # The operator's queue: what the system could not resolve alone.
            sql += " AND band IN ('auto_alarm','review')"
        if camera_id:
            sql += " AND camera_id = ?"
            args.append(camera_id)
        if state:
            sql += " AND state = ?"
            args.append(state)
        if since:
            sql += " AND ts >= ?"
            args.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            return [self._row(r) for r in c.execute(sql, args).fetchall()]

    def alert(self, alert_uid: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM alerts WHERE alert_uid = ?",
                          (alert_uid,)).fetchone()
            return self._row(r) if r else None

    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        for key in ("box", "attributes", "decision"):
            if d.get(key):
                try:
                    d[key] = json.loads(d[key])
                except (ValueError, TypeError):
                    pass
        return d

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
            by_sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
            by_state = {r["state"]: r["n"] for r in c.execute(
                "SELECT state, COUNT(*) n FROM alerts GROUP BY state")}
            occ = c.execute(
                "SELECT COALESCE(SUM(occurrences),0) n FROM alerts").fetchone()["n"]
            by_band = {r["band"]: r["n"] for r in c.execute(
                "SELECT band, COUNT(*) n FROM alerts GROUP BY band")}
        return {"alerts": total, "occurrences": occ,
                "by_severity": by_sev, "by_state": by_state,
                "by_band": by_band}

    # ------------------------------------------------------------------
    # cameras
    # ------------------------------------------------------------------
    def upsert_camera(self, cam: Dict[str, Any]) -> None:
        cam = dict(cam)
        cam["updated_ts"] = time.time()
        for key in ("capabilities", "optics"):
            if isinstance(cam.get(key), (dict, list)):
                cam[key] = json.dumps(cam[key])
        cols = list(cam)
        updates = ", ".join(f"{k}=excluded.{k}" for k in cols
                            if k != "camera_id")
        sql = (f"INSERT INTO cameras ({','.join(cols)}) "
               f"VALUES ({','.join('?' * len(cols))}) "
               f"ON CONFLICT(camera_id) DO UPDATE SET {updates}")
        with self._lock, self._conn() as c:
            c.execute(sql, [cam[k] for k in cols])

    def cameras(self) -> List[dict]:
        with self._conn() as c:
            out = []
            for r in c.execute("SELECT * FROM cameras ORDER BY camera_id"):
                d = dict(r)
                for key in ("capabilities", "optics"):
                    if d.get(key):
                        try:
                            d[key] = json.loads(d[key])
                        except (ValueError, TypeError):
                            pass
                out.append(d)
            return out

    # ------------------------------------------------------------------
    # audit (hash chain)
    # ------------------------------------------------------------------
    def audit(self, actor: str, action: str, subject: str = "",
              detail: Any = "") -> str:
        payload = detail if isinstance(detail, str) else json.dumps(
            detail, sort_keys=True, default=str)
        ts = time.time()
        with self._lock, self._conn() as c:
            prev = c.execute(
                "SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"] if prev else GENESIS
            material = f"{prev_hash}|{ts}|{actor}|{action}|{subject}|{payload}"
            digest = hashlib.sha256(material.encode()).hexdigest()
            c.execute(
                "INSERT INTO audit (ts, actor, action, subject, detail, "
                "prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, subject, payload, prev_hash, digest))
        return digest

    def audit_entries(self, limit: int = 200) -> List[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    def verify_audit(self) -> dict:
        """Walk the chain and report the first break, if any."""
        with self._conn() as c:
            rows = c.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
        prev_hash = GENESIS
        for r in rows:
            material = (f"{prev_hash}|{r['ts']}|{r['actor']}|{r['action']}|"
                        f"{r['subject']}|{r['detail']}")
            expect = hashlib.sha256(material.encode()).hexdigest()
            if r["prev_hash"] != prev_hash or expect != r["hash"]:
                return {"valid": False, "entries": len(rows),
                        "broken_at": r["id"]}
            prev_hash = r["hash"]
        return {"valid": True, "entries": len(rows), "head": prev_hash}

    # ------------------------------------------------------------------
    # active-learning labels
    # ------------------------------------------------------------------
    def add_label(self, alert_uid: str, verdict: str, actor: str,
                  note: str = "") -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO labels (ts, alert_uid, verdict, actor, note)"
                      " VALUES (?,?,?,?,?)",
                      (time.time(), alert_uid, verdict, actor, note))

    def labels(self, limit: int = 500) -> List[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM labels ORDER BY id DESC LIMIT ?", (limit,))]
