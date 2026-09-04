# Prahari

**AI-Based Intelligent Video Analytics Platform for Border Surveillance using
existing CCTV Infrastructure** — SIH26187, Ministry of Home Affairs / Sashastra
Seema Bal.

*Persistent Real-time Analytics for Hazard Alerting & Response on Installed
cameras.*

Prahari turns whatever CCTV is already bolted to the poles at a border outpost
into an intrusion-detection and alerting system. No smart cameras, no FRS
appliance, no ANPR box, no procurement cycle.

---

## The thing that actually matters

Three words in the problem statement decide the whole design: **"using existing
CCTV infrastructure"**. That means mixed brands, analog channels hanging off
2016-era DVRs, ONVIF switched off, and a single 4G dongle holding up the site.
Two consequences drive everything here:

**Ingest is the hard problem, not detection.** Anyone can run a detector.
Connecting to a nine-year-old CP Plus DVR whose ONVIF service is disabled, over
a link that drops every afternoon, is where projects fail. So the discovery
ladder is the centrepiece, and it works: **254 hosts scanned in 1.6 seconds,
four brands identified, nine cameras enumerated, zero URLs typed by a human.**

**Not every camera can do every capability.** A camera watching 400 m of open
ground will never read a number plate or match a face. Prahari measures what
each view can resolve and enables only what the optics honestly support —
showing the operator *why* a capability is greyed out. That honesty is the
strongest thing in the project.

---

## Quick start

Works the same on Windows, macOS and Linux — no make, no bash required:

```
pip install -r requirements.txt
python -m prahari.run demo
```

That renders the footage (~60 s, once), starts the DVR farm, the mock C2 and
the server, scans for the DVRs, connects every camera, and prints the
dashboard URL: **http://127.0.0.1:8000**. Ctrl-C stops everything.

Other commands:

```
python -m prahari.run footage    render the synthetic footage and exit
python -m prahari.run farm       just the simulated DVRs
python -m prahari.run server     just the control plane
python -m prahari.run scan       print the discovery ladder to the console
```

Verification:

```
python -m tests.test_alerts      deterministic suppression checks
python -m tests.test_autonomy    unsupervised baseline + decision bands
python -m tests.test_e2e         full end-to-end, against the running stack
```

On Linux the `Makefile` and `scripts/*.sh` wrappers also work
(`make demo`, `make test`, `make stop`).

### Alias mode and port mode

Linux routes the whole `127.0.0.0/8` block to loopback, so each simulated DVR
takes its own address and a genuine subnet scan finds them:

```
127.0.0.11:554  Hikvision      127.0.0.13:554  Uniview
127.0.0.12:554  CP Plus        127.0.0.14:554  Axis
```

**Windows and macOS route only `127.0.0.1`**, so that layout cannot bind
there. The simulator detects this by attempting a bind — not by sniffing the
platform name — and falls back to one address with a port per device:

```
127.0.0.1:8554  Hikvision      127.0.0.1:8556  Uniview
127.0.0.1:8555  CP Plus        127.0.0.1:8557  Axis
```

Everything else is identical, and both modes pass the same 37 end-to-end
checks. Force one with `PRAHARI_SIM_MODE=alias|port`. The dashboard asks the
farm which spec to scan, so **Scan network** does the right thing either way.

Port mode costs two things, honestly:

- **WS-Discovery (rung 1) cannot work** — only one listener can hold UDP 3702
  on one address. The ladder falls through to probing the ONVIF service ports
  directly, and each candidate must prove ownership by returning stream URIs
  that point back at that exact RTSP port.
- **The web UI cannot be attributed.** An HTTP banner belongs to an *address*,
  not to an RTSP endpoint, so with four DVRs behind one address it is skipped
  rather than guessed. That is why CP Plus reports as its Dahua family in port
  mode: the OEM badge exists only on the device web page. The RTSP `Server:`
  header, which *is* per-endpoint, still drives the brand prior.

This is not a simulator quirk. Several DVRs port-forwarded onto one public
address is a completely ordinary field deployment, and it is exactly where
naive discovery tools merge cameras from different devices.

---

## What is running

```
  simulated DVR farm                    Prahari
  ─────────────────────                 ───────────────────────────────────
  127.0.0.11  Hikvision  4ch  ONVIF off   ┌─ CAL ──────────┐
  127.0.0.12  CP Plus    2ch  ONVIF off   │ discovery      │
  127.0.0.13  Uniview    2ch  ONVIF on ──►│ brand library  │
  127.0.0.14  Axis       1ch  ONVIF on    │ role profiler  │
                                          └───────┬────────┘
  real RTSP · real H.264 · real digest            │ frames
  auth · brand-correct 404s                       ▼
                                          ┌─ perception ───┐
                                          │ detect → track │
                                          │ → rules        │
                                          │ → FAR cascade  │
                                          └───────┬────────┘
                                                  │ events
                                                  ▼
                                          ┌─ control ──────┐
                                          │ alert lifecycle│
                                          │ dedup / storm  │
                                          │ evidence + hash│
                                          └───────┬────────┘
                                                  │
                       ONVIF Profile M ◄──────────┤
                       REST / webhook             │
                       CEF → SIEM                 ▼
                       MQTT              mock C2 / any VMS
```

The DVR farm is **not** a stub. It is an RTSP 1.0 server that speaks
OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN, Basic and Digest auth, and delivers real
H.264 over RTP interleaved on TCP. `ffprobe`, VLC and OpenCV all treat it as a
physical device. Each box answers only its own brand's URL dialect and returns
`404` for everyone else's — the 404s are what actually prove the ladder.

---

## The discovery ladder

Seven rungs, first one that yields a stream wins. Rungs 1–3 are the polite
standards path; 4–7 are what make it work on hardware that shipped with ONVIF
disabled.

| # | Rung | What it does |
|---|------|--------------|
| 1 | WS-Discovery | multicast + unicast Probe on `3702`; devices announce themselves |
| 2 | ONVIF `GetDeviceInformation` | manufacturer, model, firmware, serial |
| 3 | ONVIF `GetProfiles`/`GetStreamUri` | the device hands back its own URLs — authoritative |
| 4 | Port fingerprint | `554`, `80`, `8000` Hikvision, `37777` Dahua, `8899` ONVIF-alt |
| 5 | MAC OUI | offline IEEE lookup; works when every service is locked down |
| 6 | Template probing | parallel RTSP `DESCRIBE` across the brand library, first `200 OK` wins |
| 7 | Channel enumeration | walk channels 1…N until two consecutive misses |

Adding a vendor is a change to **`config/brands.yaml` only** — never to code.

One detail worth knowing: **CP Plus is a Dahua OEM.** Identical RTSP dialect,
identical `Server:` header. The only place the actual badge on the box appears
is the login-page title, so that is what the brand prior reads. Most tools get
this wrong and report Dahua.

---

## Capability gating (the honest bit)

Thresholds are derived from anthropometry and the Indian plate standard, not
asserted — see `prahari/cal/optics.py`.

| Capability | Needs | Person height in frame |
|------------|-------|------------------------|
| Human detection | 20 px person | **20 px** |
| Pose / activity | 60 px person | **60 px** |
| Face **detection** | 16 px face width | **182 px** |
| ANPR | 100 px plate width | **340 px** |
| Face **matching** | 40 px eye spacing | **1081 px** |

That last row is the uncomfortable one, and it is why this is in code rather
than in a slide: face *recognition* needs a person occupying most of a 720p
frame. It belongs on a doorway camera, not on any border view. Prahari profiles
every camera from the median observed person height, assigns a role
(perimeter / approach / chokepoint), and lights up only what is achievable.

Hover any greyed-out badge in the dashboard and it tells you the number:
*"plates ~18 px wide here, OCR needs 100"*.

---

## The nine mandated capabilities

| # | Capability | Status | Where |
|---|-----------|--------|-------|
| 01 | Human detection & tracking | **built** | `perception/detect.py`, `track.py` |
| 02 | Vehicle detection & classification | **built** | shared detector, track-voted class |
| 03 | Face detection | interface + gating | gated off where optics forbid it |
| 04 | ANPR | interface + gating | gated off where optics forbid it |
| 05 | Virtual-fence intrusion | **built** | `perception/rules.py` — directional, ground-plane |
| 06 | Suspicious activity | partial | trajectory + dwell + loitering built; pose is P3 |
| 07 | Night-time movement | **built** | auto IR-mode detection, night policy |
| 08 | Real-time alerts & logging | **built** | `server/alerts.py`, `store.py` |
| 09 | C2 integration | **built** | `server/northbound.py` — ONVIF Profile M |

Capabilities 03 and 04 have their pipelines specified and their gating
enforced, but the recognition models are Phase 2 — they need weights trained on
Kaggle. The gating is live now, which is the part that changes the architecture.

---

## Northbound: ONVIF Profile M

Prahari does not ask a sector HQ to replace its VMS. It acts as an **analytics
integration gateway**: proprietary SDKs southbound, standards northbound.

Profile M standardises exactly what we produce — bounding boxes, centre of
gravity, class labels including `Face` and `LicensePlate`, geolocation,
confidence — as ONVIF Scene Description XML in an RTP metadata stream, over the
ONVIF Events service, and as JSON over MQTT. **Milestone XProtect, Genetec,
Axis, Bosch and Hanwha consume it with no adapter written for us.**

```bash
curl localhost:8000/api/northbound/profile-m/<alert_uid>.xml    # Scene Description
curl localhost:8000/api/northbound/onvif-event/<alert_uid>.xml  # Events topic
curl localhost:8000/api/northbound/cef/<alert_uid>              # CEF for SIEM
```

The gap worth naming out loud in a pitch: Hikvision and Dahua — the brands
actually installed across most Indian sites — remain proprietary-SDK. Prahari
bridges both directions. That is precisely the gateway role.

`prahari/tools/mock_c2.py` is a stand-in C2 that prints each payload as a third
party receives it. Run it beside the demo; it is the answer to *"how does this
reach our control room?"*, which is the question that sinks teams who only
built a dashboard.

---

## Deciding without a person

The standing objection to every video-analytics system is "who sits and
reads all these alerts?" At a border outpost at 03:00 the honest answer is
nobody, so the system has to make the call itself — and be wrong in the
safe direction.

**Every camera learns its own habits**, unsupervised, from ordinary traffic
(`prahari/perception/normality.py`). No labels, no training run, no GPU —
just counting: when movement normally happens here by hour and weekday,
where in this frame people normally walk, how fast, how big, how long they
stay. Anomaly becomes a measurable quantity rather than an opinion:

```
09:20, on the usual path   → 0.11   nothing unusual
03:12, on the usual path   → 0.51   nothing normally moves here at this hour
03:12, off any used path   → 0.83   and nothing has ever walked there
```

Baselines persist to disk. An outpost that loses power weekly would
otherwise never reach maturity, and until a camera *is* mature it is not
allowed to dismiss anything.

**Three bands, not two** (`prahari/server/autonomy.py`):

| Band | What happens | Who is involved |
|------|--------------|-----------------|
| `AUTO_ALARM` | siren, radio, priority to the control room | nobody was needed |
| `REVIEW` | queued for whenever a person is next free | a person, eventually |
| `AUTO_LOG` | recorded, hashed, searchable, shown to nobody | nobody |

What separates them is not one model's confidence — a confident detector is
exactly how false alarms happen. It is **corroboration**: independent
signals agreeing at once. Rule severity, track solidity, the learned
anomaly, whether another camera saw it, whether more than one rule fired,
and whether the view can physically support the claim being made.

Three details that took a working prototype to get right:

- **Track solidity gates, it does not add.** A confidently observed routine
  crossing is still routine. As an additive term it pushed every clean
  daytime track into the review queue — the exact flood the layer exists to
  stop.
- **A mature baseline argues both ways.** An anomaly score that can only
  add can never let a camera say "I have seen this a thousand times". Once
  mature, strong familiarity discounts the score.
- **Corroboration is weighted by anomaly.** Nine cameras reporting a
  routine crossing at 09:00 is a shift change, not an incident. Agreement
  between things that are each surprising is evidence; agreement between
  things that are each ordinary is a timetable.

**Fail-safe, never fail-quiet.** Camera tamper and alert storms can never
be silenced. Critical zones are never auto-logged. A camera whose baseline
is immature dismisses nothing. A claim the optics cannot support is
downgraded rather than trusted. The worst outcome for this system is not a
needless siren — it is a silent one.

**The alarm reaches the physical world** (`prahari/server/alarm.py`): a
relay/GPIO line for the hooter on the wall, a webhook for SMS or radio
dispatch, priority into the C2. An unacknowledged alarm escalates up the
chain on its own and keeps escalating until someone answers.

```
python -m prahari.run seed-baseline    # a synthetic fortnight, for demos
curl -XPOST localhost:8000/api/alarm/test
curl localhost:8000/api/autonomy
```

The headline metric is **alerts per hour that actually need a human**,
shown in the dashboard header. In the deterministic test, 400 routine
events reach zero operators while a 03:12 off-path crossing scores 0.67 and
sounds the siren unaided.

One caveat stated plainly: the simulator loops 20 seconds of footage on
nine cameras, so it generates roughly a hundred times the track density of
a real border camera, and the baseline adapts to that quickly. The
mechanism is proved deterministically in `tests/test_autonomy.py`; the live
numbers are a stress test, not a field measurement.

---

## False alarms

Operators switch off any system that cries wolf, so the headline metric is
**false alarms per camera per hour**, not mAP.

Five cascade stages — stages 1–2 in the detector, 3–5 in `perception/cascade.py`:

1. motion gate — static scene, sensor noise, compression shimmer
2. detection — foliage, water ripple, shadow
3. temporal confirmation — flicker, insects on the IR lens, rain streaks
4. class verification — **cattle and stray dogs**, the number-one false alarm here
5. contextual policy — lawful daytime movement in a free-movement corridor

Then, at alert level: per-track dedup, cooldown windows, cross-camera incident
joining, and storm protection that raises *one* "anomalous alert rate" meta-alert
instead of five hundred rows.

The first unfiltered run of this pipeline produced **1,350 alerts/hour**. That
number is in the repo history on purpose — it is what alert fatigue looks like,
and it is why the suppression layer exists.

---

## Detector backends

| Backend | Use | Needs |
|---------|-----|-------|
| `motion` | default; CPU-only outposts and this demo | nothing |
| `hog` | sanity check against a learned model | nothing |
| `yolo` | **production** | ultralytics + weights |
| `tiled` | motion-gated SAHI for long-range targets | wraps any of the above |

```bash
pip install ultralytics
yolo export model=yolo26s.pt format=engine half=True imgsz=1280
PRAHARI_DETECTOR=yolo scripts/server.sh restart
```

`MotionGatedTiles` is the long-range trick: blanket tiled inference costs
10–20×, so run background subtraction first and slice only the tiles that
flagged motion. It reports its own savings via `.savings`.

---

## Layout

```
config/brands.yaml         the brand URL library — edit this, not code
prahari/sim/               DVR farm: RTSP server, ONVIF responder, footage
prahari/cal/               Camera Abstraction Layer: ladder, optics, brands
prahari/perception/        detect, track, ground-plane rules, FAR cascade
prahari/server/            FastAPI, alert lifecycle, store, northbound
prahari/tools/             mock C2
tests/test_e2e.py          end-to-end verification
scripts/                   farm.sh, server.sh, c2.sh
```

---

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `PRAHARI_DETECTOR` | `motion` | `motion` \| `hog` \| `yolo` \| `tiled` |
| `PRAHARI_DB` | `prahari.db` | SQLite path (PostgreSQL/TimescaleDB in production) |
| `PRAHARI_EVIDENCE` | `evidence` | evidence clip directory |
| `PRAHARI_BRANDS` | `config/brands.yaml` | brand library path |
| `PRAHARI_FARM` | `http://127.0.0.1:9099` | simulator control API |
| `PRAHARI_SIM_MODE` | auto | force `alias` or `port` endpoint layout |
| `PRAHARI_SIM_HOST` | `127.0.0.1` | address the simulator binds in port mode (set this in Docker) |
| `PRAHARI_FARM_HOST` | `127.0.0.1` | address the farm control API binds |
| `PRAHARI_ALARM_THRESHOLD` | `0.62` | score at or above which the siren sounds unaided |
| `PRAHARI_REVIEW_THRESHOLD` | `0.30` | score below which nobody is told |
| `PRAHARI_BASELINE_MIN_HOURS` | `6` | how long a camera must watch before it may dismiss anything |
| `PRAHARI_PREVIEW_FPS` | `6` | video-wall tile refresh rate |
| `PRAHARI_NO_AUTOSTART` | unset | set to `1` to stop the server resuming cameras on boot |

---

## What is deliberately not here yet

Named so nobody mistakes scaffolding for substance:

- **Face and plate recognition models** — pipelines and gating are in; weights
  are Phase 2 on Kaggle.
- **Pose-based activity** (capability 06) — trajectory, dwell and loitering
  work; RTMPose → ST-GCN is Phase 3.
- **Cross-camera ReID** — incidents currently join on time; the OSNet embedding
  in Qdrant is Phase 3.
- **WebRTC live view** — MJPEG here so it runs anywhere; MediaMTX/WHEP is the
  production path for sub-second latency at scale.
- **TensorRT / DeepStream** — the export path is documented, not exercised, as
  this container has no GPU.

---

*Working prototype for Smart India Hackathon 2026. Synthetic footage and
simulated devices throughout; no real surveillance data is included.*
