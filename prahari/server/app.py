"""Prahari control plane: FastAPI + WebSocket + northbound fan-out.

Deliberate constraint: the dashboard is a pure client of the same public
API a command-and-control system uses. If the built-in UI had a private
back door, the integration story would be fiction -- and a technical judge
would find it. Every panel you see is reachable over /api.

Live video here is MJPEG, which works in any browser with no dependency.
Production is MediaMTX re-publishing RTSP as WebRTC/WHEP for sub-second
latency and many more streams; the endpoint below is the demo path.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional

import cv2
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..cal.discovery import Discoverer, DiscoveryReport
from ..perception.cascade import FalseAlarmCascade, ZonePolicy
from ..perception.rules import (GroundPlane, NightMovement, RuleEngine,
                                Severity, Tamper, Tripwire, Zone)
from ..perception.worker import CameraWorker
from ..perception.normality import NormalityStore
from .alarm import AlarmDispatcher, NotifySink, RelaySink
from .alerts import AlertManager
from .autonomy import AutonomyEngine, AutonomyPolicy, Band
from .northbound import (Northbound, SyslogCefEmitter, WebhookEmitter,
                         cef, onvif_notification, profile_m_json,
                         scene_description)
from .store import Store

log = logging.getLogger("prahari.server")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
EVIDENCE_DIR = os.environ.get("PRAHARI_EVIDENCE", "evidence")
DETECTOR = os.environ.get("PRAHARI_DETECTOR", "motion")
FARM_CONTROL = os.environ.get("PRAHARI_FARM", "http://127.0.0.1:9099")

app = FastAPI(title="Prahari", version="0.1",
              description="AI video analytics for border surveillance on "
                          "existing CCTV infrastructure (SIH26187)")

store = Store(os.environ.get("PRAHARI_DB", "prahari.db"))
northbound = Northbound()
workers: Dict[str, CameraWorker] = {}
engines: Dict[str, RuleEngine] = {}
_last_discovery: Optional[dict] = None
_loop: Optional[asyncio.AbstractEventLoop] = None

# The discovery report carries the ladder reasoning -- how each device was
# identified -- which is the most useful thing on the operator's screen and
# is expensive to recompute. Persist it beside the database so a restart
# does not blank the panel.
DISCOVERY_CACHE = os.path.join(
    os.path.dirname(os.environ.get("PRAHARI_DB", "prahari.db")) or ".",
    "discovery.json")


def _save_discovery(report: dict) -> None:
    try:
        with open(DISCOVERY_CACHE, "w") as fh:
            json.dump(report, fh)
    except OSError:
        log.warning("could not cache discovery report")


# Northbound consumers must outlive a reboot. A control room that stops
# receiving events because the outpost appliance restarted at 03:00, and
# nobody noticed until morning, is the same class of failure as cameras
# that do not auto-resume.
CONSUMERS_FILE = os.path.join(
    os.path.dirname(os.environ.get("PRAHARI_DB", "prahari.db")) or ".",
    "northbound.json")


def _save_consumers(urls: List[str]) -> None:
    try:
        with open(CONSUMERS_FILE, "w") as fh:
            json.dump({"webhooks": sorted(set(urls))}, fh)
    except OSError:
        log.warning("could not persist northbound consumers")


def _load_consumers() -> List[str]:
    try:
        with open(CONSUMERS_FILE) as fh:
            return list(json.load(fh).get("webhooks") or [])
    except (OSError, ValueError):
        return []


def _load_discovery() -> Optional[dict]:
    try:
        with open(DISCOVERY_CACHE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# websocket hub
# --------------------------------------------------------------------------

class Hub:
    def __init__(self):
        self.clients: List[WebSocket] = []

    async def join(self, ws: WebSocket):
        await ws.accept()
        self.clients.append(ws)

    def leave(self, ws: WebSocket):
        if ws in self.clients:
            self.clients.remove(ws)

    async def broadcast(self, kind: str, payload: dict):
        dead = []
        msg = json.dumps({"type": kind, "data": payload}, default=str)
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:                                # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.leave(ws)


hub = Hub()


def _publish(kind: str, payload: dict):
    """Called from worker threads; hops onto the event loop safely."""
    if kind == "alert":
        northbound.publish(payload)
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(hub.broadcast(kind, payload), _loop)


STATE_DIR = os.environ.get("PRAHARI_STATE", "state")
normality = NormalityStore(os.path.join(STATE_DIR, "normality.json"))
autonomy = AutonomyEngine(AutonomyPolicy.from_env())
alarms = AlarmDispatcher(
    sinks=[RelaySink(path=os.path.join(STATE_DIR, "siren.relay"))],
    escalate_after_s=float(os.environ.get("PRAHARI_ESCALATE_S", "180")))
alerts = AlertManager(store, publish=_publish, autonomy=autonomy,
                      alarms=alarms)


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------

class ScanRequest(BaseModel):
    # Default suits Linux alias mode. Windows and macOS run the simulator in
    # port mode, and the dashboard asks the farm for the right spec.
    hosts: str = "127.0.0.0/24"
    max_channels: int = 8


class StartRequest(BaseModel):
    camera_ids: Optional[List[str]] = None
    quality: str = "sub"           # sub-stream to the AI, per the link policy
    detector: Optional[str] = None


class LineRequest(BaseModel):
    camera_id: str
    a: List[float]
    b: List[float]
    direction: str = "both"
    names: List[str] = ["Nepal-bound", "India-bound"]
    severity: str = "high"
    name: str = "virtual fence"


class ZoneRequest(BaseModel):
    camera_id: str
    polygon: List[List[float]]
    dwell_s: float = 2.0
    loiter_s: float = 20.0
    severity: str = "medium"
    name: str = "restricted zone"
    criticality: str = "normal"


class AdjudicateRequest(BaseModel):
    verdict: str
    actor: str = "operator"
    note: str = ""


class LinkRequest(BaseModel):
    preset: str
    ip: Optional[str] = None


class WebhookRequest(BaseModel):
    url: str


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------

@app.on_event("startup")
async def _startup():
    global _loop
    _loop = asyncio.get_running_loop()
    store.audit("system", "server.start", "prahari",
                {"detector": DETECTOR})
    log.info("Prahari server up (detector=%s)", DETECTOR)

    global _last_discovery
    _last_discovery = _load_discovery()

    for url in _load_consumers():
        northbound.add(WebhookEmitter(url=url))
    if northbound.emitters:
        log.info("restored %d northbound consumer(s)", len(northbound.emitters))

    # Resume every known camera. A border outpost appliance that loses power
    # at 03:00 has nobody present to press "Connect all" -- it must come back
    # watching on its own. Set PRAHARI_NO_AUTOSTART=1 to disable.
    if os.environ.get("PRAHARI_NO_AUTOSTART"):
        return
    known = store.cameras()
    if known:
        started = await start_cameras(StartRequest(quality="sub"))
        log.info("auto-resumed %d camera(s) after start",
                 len(started.get("started", [])))
        store.audit("system", "cameras.autoresume", "",
                    {"count": len(started.get("started", []))})


@app.on_event("shutdown")
async def _shutdown():
    for w in workers.values():
        w.stop()
    northbound.stop()
    alarms.stop()
    normality.save(force=True)
    store.audit("system", "server.stop", "prahari")


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

@app.post("/api/discover")
async def discover(req: ScanRequest):
    global _last_discovery
    t0 = time.time()
    report = await Discoverer().scan(req.hosts, req.max_channels)
    _last_discovery = report.as_dict()
    _save_discovery(_last_discovery)

    registered = 0
    for dev in report.devices:
        for ch in dev.channels:
            main = dev.stream_for(ch, "main")
            sub = dev.stream_for(ch, "sub") or main
            if not main:
                continue
            # Include the port: in the simulator's port mode (and behind a
            # NAT with several DVRs forwarded onto one address) the IP alone
            # is not unique, and colliding ids would silently merge cameras.
            host_key = dev.ip.replace(".", "-")
            if dev.port != 554:
                host_key = f"{host_key}-p{dev.port}"
            cam_id = f"{host_key}-ch{ch}"
            store.upsert_camera({
                "camera_id": cam_id,
                "name": f"{dev.label or dev.brand} ch{ch}",
                "device_ip": dev.ip, "brand": dev.brand,
                "model": dev.model, "channel": ch,
                "url_main": main.url, "url_sub": sub.url if sub else main.url,
                "role": "unknown", "capabilities": {}, "optics": {},
                "bop": dev.ip.split(".")[-1],
            })
            registered += 1
    store.audit("operator", "network.scan", req.hosts,
                {"devices": len(report.devices), "cameras": registered})
    await hub.broadcast("discovery", report.as_dict())
    return {"report": report.as_dict(), "registered": registered,
            "elapsed_s": round(time.time() - t0, 2)}


@app.get("/api/discovery")
async def last_discovery():
    return _last_discovery or {"devices": []}


# --------------------------------------------------------------------------
# cameras
# --------------------------------------------------------------------------

def _default_rules(cam_id: str, name: str) -> RuleEngine:
    """A camera is useful the moment it connects, not after configuration.

    Sensible defaults, drawn in normalised coordinates and scaled to the
    first frame: a vertical tripwire slightly left of centre and a
    restricted zone on the right-hand side.
    """
    eng = RuleEngine(cam_id, fps=12)
    eng.tamper = Tamper()
    eng.add(Tripwire("fence-default", (620.0, 250.0), (620.0, 719.0),
                     direction="both",
                     names=("Nepal-bound", "India-bound"),
                     severity=Severity.HIGH, name=f"{name} tripwire",
                     labels=None))
    eng.add(Zone("zone-default",
                 [(720, 300), (1279, 300), (1279, 719), (720, 719)],
                 dwell_s=2.0, loiter_s=20.0, severity=Severity.MEDIUM,
                 name="restricted apron"))
    eng.add(NightMovement("night-default", name="curfew area"))
    return eng


@app.post("/api/cameras/start")
async def start_cameras(req: StartRequest):
    cams = store.cameras()
    wanted = set(req.camera_ids) if req.camera_ids else {c["camera_id"] for c in cams}
    started = []
    for cam in cams:
        cid = cam["camera_id"]
        if cid not in wanted or cid in workers:
            continue
        url = cam["url_sub"] if req.quality == "sub" else cam["url_main"]
        if not url:
            continue
        eng = engines.get(cid) or _default_rules(cid, cam.get("name") or cid)
        engines[cid] = eng
        casc = FalseAlarmCascade(default_policy=ZonePolicy(
            criticality="normal", free_movement_daytime=False))
        w = CameraWorker(cid, url, name=cam.get("name") or cid,
                         engine=eng, cascade=casc,
                         on_event=lambda ev, meta, c=cam: alerts.handle(
                             ev, {**meta, "bop": c.get("bop", "")}),
                         evidence_dir=EVIDENCE_DIR,
                         detector_kind=req.detector or DETECTOR,
                         target_fps=12,
                         normality=normality.get(cid))
        w.start()
        workers[cid] = w
        started.append(cid)
    store.audit("operator", "cameras.start", ",".join(started),
                {"count": len(started), "quality": req.quality})
    return {"started": started, "running": list(workers)}


@app.post("/api/cameras/stop")
async def stop_cameras(req: StartRequest):
    ids = req.camera_ids or list(workers)
    for cid in ids:
        w = workers.pop(cid, None)
        if w:
            w.stop()
    return {"stopped": ids, "running": list(workers)}


@app.get("/api/cameras")
async def list_cameras():
    out = []
    for cam in store.cameras():
        cid = cam["camera_id"]
        w = workers.get(cid)
        cam["running"] = bool(w)
        cam["status"] = w.status.as_dict() if w else None
        if w:
            cam["role"] = w.status.role
            cam["capabilities"] = w.status.capabilities
            cam["optics"] = w.status.optics
            store.upsert_camera({
                "camera_id": cid, "role": w.status.role,
                "capabilities": w.status.capabilities,
                "optics": w.status.optics})
        out.append(cam)
    return {"cameras": out, "running": len(workers)}


@app.get("/api/cameras/{camera_id}/snapshot.jpg")
async def snapshot(camera_id: str, w: int = 0, annotate: int = 1,
                   q: int = 0):
    """One frame, optionally downscaled.

    The grid polls this rather than holding an MJPEG stream open per tile:
    browsers cap concurrent connections per origin at about six on
    HTTP/1.1, so a nine-camera wall silently leaves three tiles black
    forever. Short-lived requests release the connection and every tile
    updates.
    """
    worker = workers.get(camera_id)
    if not worker:
        raise HTTPException(404, "camera not running")

    # Fast path: the worker already rendered this frame once. Serving those
    # bytes costs nothing, so ten browsers watching cost the same as one.
    if annotate and not w and not q:
        cached = worker.preview()
        if cached:
            return StreamingResponse(
                iter([cached]), media_type="image/jpeg",
                headers={"Cache-Control": "no-store"})

    frame = worker.snapshot()
    if frame is None:
        raise HTTPException(503, "no frame yet")
    if annotate:
        frame = _annotate(worker, frame)
    if w and w > 0 and w < frame.shape[1]:
        scale = w / frame.shape[1]
        frame = cv2.resize(frame, (w, max(1, int(frame.shape[0] * scale))),
                           interpolation=cv2.INTER_AREA)
    ok, buf = cv2.imencode(".jpg", frame,
                           [cv2.IMWRITE_JPEG_QUALITY,
                            max(30, min(q or 70, 95))])
    if not ok:
        raise HTTPException(500, "encode failed")
    return StreamingResponse(
        iter([buf.tobytes()]), media_type="image/jpeg",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"})


@app.get("/api/cameras/{camera_id}/stream.mjpg")
async def mjpeg(camera_id: str):
    w = workers.get(camera_id)
    if not w:
        raise HTTPException(404, "camera not running")

    async def gen():
        boundary = b"--frame\r\n"
        while camera_id in workers:
            frame = w.snapshot()
            if frame is not None:
                frame = _annotate(w, frame)
                ok, buf = cv2.imencode(".jpg", frame,
                                       [cv2.IMWRITE_JPEG_QUALITY, 70])
                if ok:
                    yield (boundary + b"Content-Type: image/jpeg\r\n"
                           + f"Content-Length: {len(buf)}\r\n\r\n".encode()
                           + buf.tobytes() + b"\r\n")
            await asyncio.sleep(1 / 12)

    return StreamingResponse(
        gen(), media_type="multipart/x-mixed-replace; boundary=frame")


def _annotate(w: CameraWorker, frame):
    """Boxes, track ids and the configured rules, drawn on the live view."""
    out = frame.copy()
    eng = engines.get(w.camera_id)
    if eng:
        import numpy as np
        for rule in eng.rules:
            if isinstance(rule, Tripwire):
                cv2.line(out, (int(rule.a[0]), int(rule.a[1])),
                         (int(rule.b[0]), int(rule.b[1])), (0, 165, 255), 2)
            elif isinstance(rule, Zone):
                cv2.polylines(out, [rule.polygon.astype(np.int32)], True,
                              (80, 200, 160), 2)
    for t in w.tracker.active:
        x1, y1, x2, y2 = (int(v) for v in t.box)
        colour = (60, 220, 120) if t.voted_label == "person" else (200, 180, 60)
        cv2.rectangle(out, (x1, y1), (x2, y2), colour, 2)
        cv2.putText(out, f"{t.voted_label} #{t.track_id}",
                    (x1, max(12, y1 - 5)), cv2.FONT_HERSHEY_SIMPLEX, 0.45,
                    colour, 1, cv2.LINE_AA)
    label = f"{w.display_name}  {w.status.fps:.0f} fps  {w.status.role}"
    if w.status.is_night:
        label += "  NIGHT"
    cv2.putText(out, label, (8, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5,
                (240, 240, 240), 1, cv2.LINE_AA)
    return out


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

@app.post("/api/rules/line")
async def set_line(req: LineRequest):
    eng = engines.get(req.camera_id)
    if not eng:
        raise HTTPException(404, "camera has no rule engine; start it first")
    eng.rules = [r for r in eng.rules if not isinstance(r, Tripwire)]
    eng.add(Tripwire("fence-1", (req.a[0], req.a[1]), (req.b[0], req.b[1]),
                     direction=req.direction,
                     names=(req.names[0], req.names[1]),
                     severity=Severity(req.severity), name=req.name))
    store.audit("operator", "rule.line", req.camera_id, req.model_dump())
    return {"ok": True, "rules": len(eng.rules)}


@app.post("/api/rules/zone")
async def set_zone(req: ZoneRequest):
    eng = engines.get(req.camera_id)
    if not eng:
        raise HTTPException(404, "camera has no rule engine; start it first")
    eng.rules = [r for r in eng.rules if not isinstance(r, Zone)]
    eng.add(Zone("zone-1", [(p[0], p[1]) for p in req.polygon],
                 dwell_s=req.dwell_s, loiter_s=req.loiter_s,
                 severity=Severity(req.severity), name=req.name))
    store.audit("operator", "rule.zone", req.camera_id, req.model_dump())
    return {"ok": True, "rules": len(eng.rules)}


@app.get("/api/rules/{camera_id}")
async def get_rules(camera_id: str):
    eng = engines.get(camera_id)
    if not eng:
        return {"rules": []}
    out = []
    for r in eng.rules:
        item = {"rule_id": r.rule_id, "type": r.rule_type, "name": r.name,
                "severity": r.severity.value}
        if isinstance(r, Tripwire):
            item.update({"a": list(r.a), "b": list(r.b),
                         "direction": r.direction, "names": list(r.names)})
        elif isinstance(r, Zone):
            item["polygon"] = r.polygon.reshape(-1, 2).tolist()
        out.append(item)
    return {"rules": out}


# --------------------------------------------------------------------------
# alerts
# --------------------------------------------------------------------------

@app.get("/api/alerts")
async def list_alerts(limit: int = 60, camera_id: Optional[str] = None,
                      state: Optional[str] = None,
                      band: Optional[str] = None,
                      needs_human: int = 0):
    """`needs_human=1` is the operator's queue: what the system could not
    resolve on its own. Everything else stays in the archive."""
    normality.save()
    return {"alerts": store.alerts(limit=limit, camera_id=camera_id,
                                   state=state, band=band,
                                   needs_human=bool(needs_human)),
            "stats": store.stats(),
            "autonomy": autonomy.metrics()}


@app.get("/api/autonomy")
async def autonomy_status():
    return {"metrics": autonomy.metrics(),
            "alarms": alarms.status(),
            "baselines": normality.summaries(),
            "policy": {"alarm_threshold": autonomy.policy.alarm_threshold,
                       "review_threshold": autonomy.policy.review_threshold}}


class ThresholdRequest(BaseModel):
    alarm_threshold: Optional[float] = None
    review_threshold: Optional[float] = None


@app.post("/api/autonomy/thresholds")
async def set_thresholds(req: ThresholdRequest):
    if req.alarm_threshold is not None:
        autonomy.policy.alarm_threshold = max(0.0, min(1.0,
                                                       req.alarm_threshold))
    if req.review_threshold is not None:
        autonomy.policy.review_threshold = max(0.0, min(1.0,
                                                        req.review_threshold))
    store.audit("operator", "autonomy.thresholds", "",
                {"alarm": autonomy.policy.alarm_threshold,
                 "review": autonomy.policy.review_threshold})
    return await autonomy_status()


class SeedRequest(BaseModel):
    days: int = 14


@app.post("/api/autonomy/seed")
async def seed_baselines(req: SeedRequest):
    """Give every camera a plausible fortnight of routine daytime history.

    A freshly installed system has no baseline, so it correctly refuses to
    dismiss anything and everything goes to a person. Right in the field,
    useless in a five-minute demo.

    Seeding happens HERE, inside the running server, on the same objects
    the workers are using. Writing the file from a separate process races
    the server's own autosave and gets silently overwritten -- which is
    exactly what happened the first time this was tried.

    Synthetic and labelled as such: a demo aid, never evidence.
    """
    import random
    rng = random.Random(7)
    now = time.time()
    seeded = []
    for cam in store.cameras():
        cid = cam["camera_id"]
        m = normality.get(cid)

        # Use the camera's REAL geometry and observed scale. Hard-coding a
        # frame size put the learned path outside a 704x396 view entirely,
        # so every cell clamped to one row and "off any path" stopped
        # meaning anything.
        worker = workers.get(cid)
        opt = (worker.status.optics if worker else {}) or {}
        fw = int(opt.get("frame_width") or getattr(
            worker, "profiler", None) and worker.profiler.frame_w or 704) or 704
        fh = int(opt.get("frame_height") or getattr(
            worker, "profiler", None) and worker.profiler.frame_h or 396) or 396
        person_px = float(opt.get("median_person_px") or 0) or fh * 0.10
        path_x, path_y = fw * 0.50, fh * 0.72

        for d in range(max(1, req.days)):
            day = now - (d + 1) * 86400
            for hour in range(24):
                # Traffic every hour, heavier by day. Seeding only daylight
                # makes any night-time demo look anomalous for the wrong
                # reason -- and a real outpost does have night patrols.
                busy = 4 if 7 <= hour <= 18 else 1
                for _ in range(rng.randint(1, busy + 1)):
                    ts = (day - (time.localtime(day).tm_hour - hour) * 3600
                          + rng.uniform(-1200, 1200))
                    m.observe(ts=ts, label="person",
                              foot_xy=(path_x + rng.gauss(0, fw * 0.10),
                                       path_y + rng.gauss(0, fh * 0.05)),
                              frame_wh=(fw, fh),
                              height_px=max(8, rng.gauss(person_px, person_px * 0.2)),
                              speed_px_s=max(2, rng.gauss(30, 9)),
                              dwell_s=max(1, rng.gauss(7, 3)))
        seeded.append(cid)
    normality.save(force=True)
    store.audit("operator", "autonomy.seed", "",
                {"cameras": len(seeded), "days": req.days,
                 "synthetic": True})
    return {"seeded": seeded, "days": req.days,
            "baselines": normality.summaries()}


@app.post("/api/alarm/test")
async def alarm_test():
    """Prove the siren path end to end without waiting for an intruder."""
    fake = {"alert_uid": "test", "camera_name": "test",
            "camera_id": "test", "message": "alarm output test"}
    fired = alarms.fire(fake, {"score": 1.0, "reasons": ["manual test"]})
    alarms.acknowledge("test")
    store.audit("operator", "alarm.test", "", {"sinks": fired})
    return {"fired": fired, "status": alarms.status()}


@app.get("/api/alerts/{alert_uid}")
async def get_alert(alert_uid: str):
    a = store.alert(alert_uid)
    if not a:
        raise HTTPException(404, "no such alert")
    return a


@app.post("/api/alerts/{alert_uid}/ack")
async def ack(alert_uid: str, actor: str = "operator"):
    a = alerts.acknowledge(alert_uid, actor)
    if not a:
        raise HTTPException(404, "no such alert")
    return a


@app.post("/api/alerts/{alert_uid}/adjudicate")
async def adjudicate(alert_uid: str, req: AdjudicateRequest):
    a = alerts.adjudicate(alert_uid, req.verdict, req.actor, req.note)
    if not a:
        raise HTTPException(404, "no such alert")
    return a


@app.get("/api/alerts/{alert_uid}/evidence")
async def evidence(alert_uid: str):
    a = store.alert(alert_uid)
    if not a or not a.get("evidence_clip"):
        raise HTTPException(404, "no evidence for this alert")
    path = a["evidence_clip"]
    if not os.path.exists(path):
        raise HTTPException(404, "evidence file missing")
    store.audit("operator", "evidence.view", alert_uid, {"path": path})
    return FileResponse(path, media_type="video/mp4")


@app.get("/api/alerts/{alert_uid}/thumbnail.jpg")
async def thumbnail(alert_uid: str):
    a = store.alert(alert_uid)
    path = (a or {}).get("thumbnail")
    if not path or not os.path.exists(path):
        raise HTTPException(404, "no thumbnail")
    return FileResponse(path, media_type="image/jpeg")


# --------------------------------------------------------------------------
# northbound (capability 09)
# --------------------------------------------------------------------------

@app.get("/api/northbound/profile-m/{alert_uid}.xml")
async def profile_m_xml(alert_uid: str):
    a = store.alert(alert_uid)
    if not a:
        raise HTTPException(404, "no such alert")
    return PlainTextResponse(scene_description(a), media_type="application/xml")


@app.get("/api/northbound/onvif-event/{alert_uid}.xml")
async def onvif_event(alert_uid: str):
    a = store.alert(alert_uid)
    if not a:
        raise HTTPException(404, "no such alert")
    return PlainTextResponse(onvif_notification(a),
                             media_type="application/xml")


@app.get("/api/northbound/cef/{alert_uid}")
async def cef_line(alert_uid: str):
    a = store.alert(alert_uid)
    if not a:
        raise HTTPException(404, "no such alert")
    return PlainTextResponse(cef(a))


@app.post("/api/northbound/webhook")
async def add_webhook(req: WebhookRequest):
    existing = [getattr(e, "url", "") for e in northbound.emitters]
    if req.url not in existing:
        northbound.add(WebhookEmitter(url=req.url))
    _save_consumers([u for u in existing + [req.url] if u])
    store.audit("operator", "northbound.webhook", req.url)
    return {"emitters": northbound.stats()}


@app.get("/api/northbound")
async def northbound_status():
    return {"emitters": northbound.stats()}


# --------------------------------------------------------------------------
# link control (proxies the simulator's impairment API)
# --------------------------------------------------------------------------

@app.post("/api/link")
async def set_link(req: LinkRequest):
    import urllib.request
    body = json.dumps({"preset": req.preset, "ip": req.ip}).encode()
    try:
        r = urllib.request.Request(f"{FARM_CONTROL}/link", data=body,
                                   method="POST",
                                   headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=3) as resp:
            out = json.loads(resp.read())
    except Exception as exc:                                  # noqa: BLE001
        raise HTTPException(502, f"farm control unreachable: {exc}")
    store.audit("operator", "link.preset", req.ip or "all",
                {"preset": req.preset})
    await hub.broadcast("link", out)
    return out


@app.get("/api/link")
async def get_link():
    import urllib.request
    try:
        with urllib.request.urlopen(f"{FARM_CONTROL}/devices", timeout=3) as r:
            return json.loads(r.read())
    except Exception:                                         # noqa: BLE001
        return {"devices": [], "presets": []}


# --------------------------------------------------------------------------
# metrics, audit, health
# --------------------------------------------------------------------------

@app.get("/api/metrics")
async def metrics():
    cams = []
    total_events = total_suppressed = 0
    for cid, w in workers.items():
        s = w.status
        total_events += s.events
        total_suppressed += s.suppressed
        cams.append({"camera_id": cid, "fps": round(s.fps, 1),
                     "connected": s.connected, "role": s.role,
                     "tracks": s.tracks, "events": s.events,
                     "suppressed": s.suppressed,
                     "reconnects": s.reconnects, "night": s.is_night,
                     "cascade": w.cascade.stats.as_dict()})
    return {
        "cameras": cams,
        "alerts": alerts.metrics(),
        "store": store.stats(),
        "northbound": northbound.stats(),
        "rule_events": total_events,
        "cascade_suppressed": total_suppressed,
        "autonomy": autonomy.metrics(),
        "alarms": alarms.status(),
    }


@app.get("/api/audit")
async def audit(limit: int = 100):
    return {"entries": store.audit_entries(limit),
            "chain": store.verify_audit()}


@app.get("/api/audit/verify")
async def audit_verify():
    return store.verify_audit()


@app.get("/api/labels")
async def labels():
    """The active-learning queue: every alert an operator called false."""
    return {"labels": store.labels()}


@app.get("/api/health")
async def health():
    return {"ok": True, "workers": len(workers), "detector": DETECTOR,
            "time": time.time()}


@app.websocket("/ws")
async def ws(sock: WebSocket):
    await hub.join(sock)
    try:
        await sock.send_text(json.dumps({"type": "hello", "data": {
            "cameras": len(store.cameras()), "running": len(workers)}}))
        while True:
            await sock.receive_text()
    except WebSocketDisconnect:
        hub.leave(sock)
    except Exception:                                         # noqa: BLE001
        hub.leave(sock)


if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
