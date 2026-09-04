"""Northbound integration (PS capability 09).

SSB sector headquarters already runs a VMS and a video wall. Prahari must
not ask them to replace it. The correct posture is an analytics
integration gateway: consume any camera southbound, emit standards-shaped
intelligence northbound, and leave the existing C2 exactly as it is.

ONVIF Profile M is the answer to give. It standardises analytics metadata
and events -- bounding boxes, centre of gravity, class labels including
Face and LicensePlate, appearance attributes, geolocation and confidence --
carried as ONVIF Scene Description XML in an RTP metadata stream, over the
ONVIF Events service, and optionally as JSON over MQTT. Emitting it means
any compliant VMS (Milestone XProtect, Genetec, Axis, Bosch, Hanwha)
ingests Prahari's alerts with no custom integration work.

The gap worth naming: Hikvision and Dahua, the brands actually installed
across most Indian sites, remain proprietary-SDK. Prahari bridges both
directions -- their dialects southbound, Profile M northbound.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from xml.sax.saxutils import escape

log = logging.getLogger("prahari.server.northbound")

VENDOR = "Prahari"
PRODUCT = "BorderVA"
VERSION = "0.1"

#: Prahari class -> ONVIF Profile M object class. Profile M defines Human,
#: Vehicle, Face, LicensePlate and Animal; everything else degrades to
#: "Other" rather than inventing a label a VMS cannot interpret.
ONVIF_CLASS = {
    "person": "Human", "animal": "Animal", "car": "Vehicle",
    "truck": "Vehicle", "bus": "Vehicle", "tempo": "Vehicle",
    "tractor": "Vehicle", "two_wheeler": "Vehicle", "cart": "Vehicle",
    "boat": "Vehicle", "face": "Face", "plate": "LicensePlate",
    "camera": "Other",
}

SEVERITY_CEF = {"info": 2, "low": 4, "medium": 6, "high": 8, "critical": 10}


def _box(alert: dict) -> List[float]:
    b = alert.get("box") or [0, 0, 0, 0]
    if isinstance(b, str):
        try:
            b = json.loads(b)
        except ValueError:
            b = [0, 0, 0, 0]
    return [float(v) for v in (list(b) + [0, 0, 0, 0])[:4]]


def _normalised(alert: dict, width: float = 1280.0,
                height: float = 720.0) -> Dict[str, float]:
    """Profile M carries a normalised frame: x,y in [-1,1], y up."""
    x1, y1, x2, y2 = _box(alert)
    return {
        "left": (x1 / width) * 2 - 1,
        "right": (x2 / width) * 2 - 1,
        "top": 1 - (y1 / height) * 2,
        "bottom": 1 - (y2 / height) * 2,
    }


# --------------------------------------------------------------------------
# ONVIF Profile M payloads
# --------------------------------------------------------------------------

def scene_description(alert: dict, width: float = 1280.0,
                      height: float = 720.0) -> str:
    """ONVIF Scene Description XML -- the mandatory Profile M metadata.

    This is the exact payload a Profile M device puts in its RTP metadata
    stream, so a VMS that already renders analytics overlays will draw
    Prahari's boxes with no adapter at all.
    """
    n = _normalised(alert, width, height)
    obj_id = abs(int(alert.get("track_id") or 0))
    cls = ONVIF_CLASS.get(str(alert.get("label", "")), "Other")
    cx = (n["left"] + n["right"]) / 2
    cy = (n["top"] + n["bottom"]) / 2
    utc = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(alert.get("ts", time.time())))
    likelihood = 0.9

    extras = ""
    attrs = alert.get("attributes") or {}
    if isinstance(attrs, str):
        try:
            attrs = json.loads(attrs)
        except ValueError:
            attrs = {}
    if alert.get("ground_x") is not None and alert.get("ground_y") is not None:
        extras += ('<tt:GeoLocation lon="{:.6f}" lat="{:.6f}" elevation="0"/>'
                   .format(float(alert["ground_y"]), float(alert["ground_x"])))
    if attrs.get("plate_text"):
        extras += ("<tt:Extension><tt:LicensePlateInfo><tt:PlateNumber>"
                   "<tt:Item>{}</tt:Item></tt:PlateNumber>"
                   "</tt:LicensePlateInfo></tt:Extension>"
                   .format(escape(str(attrs["plate_text"]))))

    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<tt:MetadataStream xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'<tt:VideoAnalytics><tt:Frame UtcTime="{utc}">'
        '<tt:Transformation>'
        '<tt:Translate x="-1.0" y="-1.0"/>'
        f'<tt:Scale x="{2.0/width:.8f}" y="{-2.0/height:.8f}"/>'
        '</tt:Transformation>'
        f'<tt:Object ObjectId="{obj_id}"><tt:Appearance>'
        f'<tt:Shape><tt:BoundingBox left="{n["left"]:.5f}" '
        f'top="{n["top"]:.5f}" right="{n["right"]:.5f}" '
        f'bottom="{n["bottom"]:.5f}"/>'
        f'<tt:CenterOfGravity x="{cx:.5f}" y="{cy:.5f}"/></tt:Shape>'
        f'<tt:Class><tt:Type Likelihood="{likelihood}">{cls}</tt:Type></tt:Class>'
        f'{extras}'
        '</tt:Appearance></tt:Object>'
        '</tt:Frame></tt:VideoAnalytics></tt:MetadataStream>'
    )


def onvif_notification(alert: dict) -> str:
    """ONVIF Events (WS-BaseNotification) message for the rule that fired."""
    topic = {
        "tripwire": "tns1:RuleEngine/LineDetector/Crossed",
        "zone_entry": "tns1:RuleEngine/FieldDetector/ObjectsInside",
        "loitering": "tns1:RuleEngine/LoiteringDetector/Loitering",
        "night_movement": "tns1:RuleEngine/MotionRegionDetector/Motion",
        "tamper": "tns1:VideoSource/ImageTooBlurry/AnalyticsService",
        "alert_storm": "tns1:Device/HardwareFailure/AnalyticsService",
    }.get(str(alert.get("rule_type")), "tns1:RuleEngine/CellMotionDetector/Motion")
    utc = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(alert.get("ts", time.time())))
    items = {
        "VideoSource": alert.get("camera_id", ""),
        "Rule": alert.get("rule_id", ""),
        "ObjectId": alert.get("track_id", 0),
        "ObjectType": ONVIF_CLASS.get(str(alert.get("label", "")), "Other"),
        "Severity": alert.get("severity", ""),
        "Direction": alert.get("direction", "") or "",
        "AlertUid": alert.get("alert_uid", ""),
    }
    simple = "".join(
        f'<tt:SimpleItem Name="{k}" Value="{escape(str(v))}"/>'
        for k, v in items.items())
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<wsnt:Notify xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" '
        'xmlns:tt="http://www.onvif.org/ver10/schema" '
        'xmlns:tns1="http://www.onvif.org/ver10/topics">'
        '<wsnt:NotificationMessage>'
        f'<wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/'
        f'ConcreteSet">{topic}</wsnt:Topic>'
        '<wsnt:Message>'
        f'<tt:Message UtcTime="{utc}" PropertyOperation="Initialized">'
        f'<tt:Source><tt:SimpleItem Name="VideoSourceConfigurationToken" '
        f'Value="{escape(str(alert.get("camera_id","")))}"/></tt:Source>'
        f'<tt:Data>{simple}</tt:Data>'
        '</tt:Message></wsnt:Message>'
        '</wsnt:NotificationMessage></wsnt:Notify>'
    )


def profile_m_json(alert: dict) -> dict:
    """Profile M's optional MQTT/JSON binding -- the same facts as the XML."""
    x1, y1, x2, y2 = _box(alert)
    return {
        "utcTime": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime(alert.get("ts", time.time()))),
        "videoSource": alert.get("camera_id"),
        "objectId": alert.get("track_id"),
        "class": ONVIF_CLASS.get(str(alert.get("label", "")), "Other"),
        "boundingBox": {"left": x1, "top": y1, "right": x2, "bottom": y2},
        "rule": {"id": alert.get("rule_id"), "type": alert.get("rule_type")},
        "severity": alert.get("severity"),
        "direction": alert.get("direction"),
        "geoLocation": ({"x_m": alert.get("ground_x"),
                         "y_m": alert.get("ground_y")}
                        if alert.get("ground_x") is not None else None),
        "alertUid": alert.get("alert_uid"),
        "message": alert.get("message"),
        "evidence": alert.get("evidence_clip") or None,
        "evidenceSha256": alert.get("evidence_sha") or None,
        "modelVersion": alert.get("model_version"),
    }


def cef(alert: dict) -> str:
    """ArcSight CEF for the SIEM the security team already watches."""
    sev = SEVERITY_CEF.get(str(alert.get("severity", "low")), 4)
    ext = {
        "rt": int(float(alert.get("ts", time.time())) * 1000),
        "cat": alert.get("rule_type", ""),
        "deviceExternalId": alert.get("camera_id", ""),
        "sourceServiceName": alert.get("camera_name", ""),
        "cs1Label": "objectClass", "cs1": alert.get("label", ""),
        "cs2Label": "direction", "cs2": alert.get("direction", "") or "-",
        "cs3Label": "alertUid", "cs3": alert.get("alert_uid", ""),
        "cn1Label": "trackId", "cn1": alert.get("track_id", 0),
    }
    body = " ".join(f"{k}={v}" for k, v in ext.items())
    msg = str(alert.get("message", "")).replace("|", "\\|")
    return (f"CEF:0|{VENDOR}|{PRODUCT}|{VERSION}|"
            f"{alert.get('rule_type','event')}|{msg}|{sev}|{body}")


# --------------------------------------------------------------------------
# emitters
# --------------------------------------------------------------------------

class Emitter:
    name = "emitter"
    enabled = True

    def send(self, alert: dict) -> bool:
        raise NotImplementedError


@dataclass
class WebhookEmitter(Emitter):
    """POST the full alert plus its Profile M payloads to a C2 endpoint."""
    url: str
    timeout: float = 3.0
    name: str = "webhook"
    enabled: bool = True
    sent: int = 0
    failed: int = 0

    def send(self, alert: dict) -> bool:
        payload = {
            "alert": alert,
            "profileM": profile_m_json(alert),
            "sceneDescriptionXml": scene_description(alert),
            "onvifNotificationXml": onvif_notification(alert),
            "cef": cef(alert),
        }
        data = json.dumps(payload, default=str).encode()
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": f"{VENDOR}-{PRODUCT}/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            self.sent += 1
            return True
        except (urllib.error.URLError, OSError) as exc:
            self.failed += 1
            log.debug("webhook %s failed: %s", self.url, exc)
            return False


@dataclass
class SyslogCefEmitter(Emitter):
    host: str = "127.0.0.1"
    port: int = 514
    facility: int = 13
    name: str = "syslog-cef"
    enabled: bool = True
    sent: int = 0
    failed: int = 0

    def send(self, alert: dict) -> bool:
        sev = SEVERITY_CEF.get(str(alert.get("severity", "low")), 4)
        pri = self.facility * 8 + (3 if sev >= 8 else 5)
        stamp = time.strftime("%b %d %H:%M:%S")
        line = f"<{pri}>{stamp} prahari {cef(alert)}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(line.encode()[:8192], (self.host, self.port))
            self.sent += 1
            return True
        except OSError:
            self.failed += 1
            return False


@dataclass
class MqttEmitter(Emitter):
    """Profile M's MQTT/JSON binding, topic per camera.

        prahari/bop/<bop>/camera/<camera_id>/alert
    """
    host: str = "127.0.0.1"
    port: int = 1883
    base_topic: str = "prahari"
    name: str = "mqtt"
    enabled: bool = True
    sent: int = 0
    failed: int = 0
    _client: object = field(default=None, repr=False)

    def connect(self) -> bool:
        try:
            import paho.mqtt.client as mqtt        # noqa: PLC0415
        except ImportError:
            log.info("paho-mqtt not installed; MQTT emitter disabled")
            self.enabled = False
            return False
        try:
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=f"prahari-{uuid.uuid4().hex[:8]}")
            client.connect(self.host, self.port, keepalive=30)
            client.loop_start()
            self._client = client
            return True
        except OSError as exc:
            log.info("MQTT broker unreachable at %s:%d (%s); "
                     "northbound MQTT disabled", self.host, self.port, exc)
            self.enabled = False
            return False

    def send(self, alert: dict) -> bool:
        if not self.enabled or self._client is None:
            return False
        topic = (f"{self.base_topic}/bop/{alert.get('bop') or 'unknown'}"
                 f"/camera/{alert.get('camera_id')}/alert")
        try:
            self._client.publish(
                topic, json.dumps(profile_m_json(alert), default=str), qos=1)
            self.sent += 1
            return True
        except Exception:                                    # noqa: BLE001
            self.failed += 1
            return False


class Northbound:
    """Fan-out to every configured C2 interface, off the hot path."""

    def __init__(self, emitters: Optional[List[Emitter]] = None,
                 workers: int = 2):
        self.emitters: List[Emitter] = emitters or []
        self._queue: List[dict] = []
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._run, daemon=True,
                             name=f"northbound-{i}")
            for i in range(workers)]
        for t in self._threads:
            t.start()

    def add(self, emitter: Emitter) -> "Northbound":
        self.emitters.append(emitter)
        return self

    def publish(self, alert: dict) -> None:
        with self._cv:
            self._queue.append(alert)
            self._cv.notify()

    def _run(self):
        while not self._stop.is_set():
            with self._cv:
                while not self._queue and not self._stop.is_set():
                    self._cv.wait(0.5)
                if self._stop.is_set():
                    return
                alert = self._queue.pop(0)
            for em in self.emitters:
                if em.enabled:
                    try:
                        em.send(alert)
                    except Exception:                        # noqa: BLE001
                        log.exception("emitter %s failed", em.name)

    def stats(self) -> List[dict]:
        return [{"name": e.name, "enabled": e.enabled,
                 "sent": getattr(e, "sent", 0),
                 "failed": getattr(e, "failed", 0)} for e in self.emitters]

    def stop(self):
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
