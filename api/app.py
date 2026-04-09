import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import joinedload, selectinload

from common.db import SessionLocal, wait_for_db
from common.models import (
    AnomalyEvent,
    AnomalyMode,
    Device,
    DeviceSettings,
    TrafficObservation,
)

FRONTEND_URLS = os.getenv(
    "FRONTEND_URLS",
    "http://localhost:5173,http://127.0.0.1:5173,http://192.168.1.5:5173",
)
ALLOWED_ORIGINS = [url.strip() for url in FRONTEND_URLS.split(",") if url.strip()]
OBS_RETENTION_MINUTES = int(os.getenv("OBS_RETENTION_MINUTES", "10"))
OBS_CLEANUP_INTERVAL_SECONDS = int(os.getenv("OBS_CLEANUP_INTERVAL_SECONDS", "30"))
LIVE_POLL_WINDOW_MINUTES = int(os.getenv("LIVE_POLL_WINDOW_MINUTES", "10"))

app = FastAPI(title="OT Monitoring API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


SUPPORTED_MODES_BY_KIND = {
    "sensor": {
        AnomalyMode.NORMAL,
        AnomalyMode.SILENT,
        AnomalyMode.BURST,
        AnomalyMode.JITTER,
        AnomalyMode.LARGE_PAYLOAD,
        AnomalyMode.NEW_PORT,
        AnomalyMode.CHANGE_IP,
        AnomalyMode.DISCONNECT,
        AnomalyMode.MALFORMED_PAYLOAD,
    },
    "hmi": {
        AnomalyMode.NORMAL,
        AnomalyMode.SILENT,
        AnomalyMode.BURST,
        AnomalyMode.JITTER,
        AnomalyMode.NEW_PORT,
        AnomalyMode.CHANGE_IP,
        AnomalyMode.DISCONNECT,
        AnomalyMode.MALFORMED_PAYLOAD,
    },
    "plc": {
        AnomalyMode.NORMAL,
        AnomalyMode.SILENT,
        AnomalyMode.DISCONNECT,
        AnomalyMode.SLOW_RESPONSE,
        AnomalyMode.MALFORMED_PAYLOAD,
        AnomalyMode.LARGE_PAYLOAD,
    },
    "detector": {
        AnomalyMode.NORMAL,
    },
    "rogue": {
        AnomalyMode.NORMAL,
    },
}


class ModeChange(BaseModel):
    mode: str


class DetectorObservationIn(BaseModel):
    window_ts: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str
    dst_port: int | None = None

    packet_count: int
    packet_rate: float
    byte_count: int
    payload_bytes: int

    avg_packet_size: float
    avg_interarrival_ms: float
    jitter_ms: float

    max_payload: int
    arp_count: int = 0
    tcp_syn_count: int = 0
    tcp_rst_count: int = 0

    ml_anomaly: bool = False
    ml_score: float | None = None


class DetectorEventCore(BaseModel):
    event_type: str
    severity: str
    title: str
    detected_at: datetime

    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    dst_port: int | None = None


def _model_field_names(model_cls) -> set[str]:
    if hasattr(model_cls, "model_fields"):
        return set(model_cls.model_fields.keys())
    return set(model_cls.__fields__.keys())


def cleanup_observations_loop() -> None:
    while True:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=OBS_RETENTION_MINUTES)

        try:
            with SessionLocal.begin() as session:
                session.execute(
                    delete(TrafficObservation).where(TrafficObservation.window_ts < cutoff)
                )
        except Exception as exc:
            print(f"[API] cleanup error: {exc}", flush=True)

        time.sleep(OBS_CLEANUP_INTERVAL_SECONDS)


def to_utc_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_timing_observation(row: TrafficObservation) -> bool:
    if row.protocol == "udp" and row.dst_port in {10001, 10002, 10003}:
        return True

    if row.protocol == "tcp" and row.dst_port == 15000:
        return True

    return False


def build_buckets(
    observations: list[TrafficObservation],
    events: list[AnomalyEvent],
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "ts": "",
            "packet_rate_sum": 0.0,
            "byte_count_sum": 0,
            "payload_bytes_sum": 0,
            "jitter_sum": 0.0,
            "jitter_samples": 0,
            "max_payload": 0,
            "flow_count": 0,
            "ml_anomaly_count": 0,
            "event_count": 0,
        }
    )

    for row in observations:
        ts = to_utc_z(row.window_ts)
        bucket = buckets[ts]
        bucket["ts"] = ts
        bucket["packet_rate_sum"] += float(row.packet_rate)
        bucket["byte_count_sum"] += int(row.byte_count)
        bucket["payload_bytes_sum"] += int(row.payload_bytes)

        if is_timing_observation(row):
            bucket["jitter_sum"] += float(row.jitter_ms)
            bucket["jitter_samples"] += 1

        bucket["max_payload"] = max(bucket["max_payload"], int(row.max_payload))
        bucket["flow_count"] += 1

        if row.ml_anomaly:
            bucket["ml_anomaly_count"] += 1

    for event in events:
        ts = to_utc_z(event.detected_at)
        bucket = buckets[ts]
        bucket["ts"] = ts
        bucket["event_count"] += 1

    result = []
    for ts in sorted(buckets.keys()):
        bucket = buckets[ts]
        result.append(
            {
                "ts": ts,
                "packet_rate_sum": round(bucket["packet_rate_sum"], 3),
                "byte_count_sum": bucket["byte_count_sum"],
                "payload_bytes_sum": bucket["payload_bytes_sum"],
                "avg_jitter_ms": round(
                    bucket["jitter_sum"] / bucket["jitter_samples"], 3
                ) if bucket["jitter_samples"] else 0.0,
                "max_payload": bucket["max_payload"],
                "flow_count": bucket["flow_count"],
                "ml_anomaly_count": bucket["ml_anomaly_count"],
                "event_count": bucket["event_count"],
            }
        )

    return result


@app.on_event("startup")
def startup() -> None:
    wait_for_db()
    threading.Thread(target=cleanup_observations_loop, daemon=True).start()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/modes")
def get_modes():
    return [mode.value for mode in AnomalyMode]


@app.get("/devices")
def get_devices():
    detector_cutoff = datetime.now(timezone.utc) - timedelta(seconds=15)

    with SessionLocal() as session:
        stmt = (
            select(Device)
            .options(joinedload(Device.settings), selectinload(Device.listen_ports))
            .where(Device.is_enabled.is_(True))
            .order_by(Device.name)
        )
        devices = session.execute(stmt).unique().scalars().all()

        recent_observation = session.execute(
            select(TrafficObservation.id)
            .where(TrafficObservation.window_ts >= detector_cutoff)
            .limit(1)
        ).scalar_one_or_none()

        recent_event = session.execute(
            select(AnomalyEvent.id)
            .where(AnomalyEvent.detected_at >= detector_cutoff)
            .limit(1)
        ).scalar_one_or_none()

        detector_status = "online" if (recent_observation or recent_event) else "offline"

        result = []
        for device in devices:
            settings = device.settings
            device_status = settings.status.value if settings else "unknown"

            if device.kind.value == "detector":
                device_status = detector_status

            result.append(
                {
                    "name": device.name,
                    "kind": device.kind.value,
                    "ip_address": str(device.ip_address),
                    "status": device_status,
                    "anomaly_mode": settings.anomaly_mode.value if settings else "normal",
                    "anomaly_active": bool(settings.anomaly_active) if settings else False,
                    "bind_ip": str(settings.bind_ip) if settings and settings.bind_ip else None,
                    "bind_port": settings.bind_port if settings else None,
                    "target_ip": str(settings.target_ip) if settings and settings.target_ip else None,
                    "target_port": settings.target_port if settings else None,
                    "supported_modes": sorted(
                        mode.value
                        for mode in SUPPORTED_MODES_BY_KIND.get(device.kind.value, {AnomalyMode.NORMAL})
                    ),
                }
            )

        return result


@app.post("/devices/{device_name}/mode")
def set_device_mode(device_name: str, payload: ModeChange):
    try:
        new_mode = AnomalyMode(payload.mode)
    except ValueError:
        raise HTTPException(status_code=400, detail="Niepoprawny tryb")

    with SessionLocal.begin() as session:
        stmt = (
            select(Device, DeviceSettings)
            .join(DeviceSettings, Device.id == DeviceSettings.device_id)
            .where(Device.name == device_name, Device.is_enabled.is_(True))
        )
        row = session.execute(stmt).one_or_none()

        if row is None:
            raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

        device, settings = row
        allowed_modes = SUPPORTED_MODES_BY_KIND.get(device.kind.value, {AnomalyMode.NORMAL})

        if new_mode not in allowed_modes:
            raise HTTPException(
                status_code=400,
                detail=f"Tryb {new_mode.value} nie jest wspierany dla urządzenia typu {device.kind.value}",
            )

        settings.anomaly_mode = new_mode
        settings.anomaly_active = new_mode != AnomalyMode.NORMAL

    return {
        "message": f"Ustawiono tryb {new_mode.value} dla {device_name}",
        "device_name": device_name,
        "mode": new_mode.value,
    }


@app.post("/detector/observations", status_code=status.HTTP_201_CREATED)
def create_detector_observation(payload: DetectorObservationIn):
    protocol = payload.protocol.lower()
    dst_port = payload.dst_port

    if protocol not in {"tcp", "udp"}:
        dst_port = None
    elif dst_port == 0:
        dst_port = None

    row = TrafficObservation(
        window_ts=payload.window_ts,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        protocol=protocol,
        dst_port=dst_port,
        packet_count=payload.packet_count,
        packet_rate=payload.packet_rate,
        byte_count=payload.byte_count,
        payload_bytes=payload.payload_bytes,
        avg_packet_size=payload.avg_packet_size,
        avg_interarrival_ms=payload.avg_interarrival_ms,
        jitter_ms=payload.jitter_ms,
        max_payload=payload.max_payload,
        arp_count=payload.arp_count,
        tcp_syn_count=payload.tcp_syn_count,
        tcp_rst_count=payload.tcp_rst_count,
        ml_anomaly=payload.ml_anomaly,
        ml_score=payload.ml_score,
    )

    with SessionLocal.begin() as session:
        session.add(row)
        session.flush()
        created_id = row.id

    return {"status": "saved", "id": str(created_id)}


@app.post("/detector/events", status_code=status.HTTP_201_CREATED)
def create_detector_event(payload: dict[str, Any]):
    try:
        core = DetectorEventCore(**payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors())

    reserved_keys = _model_field_names(DetectorEventCore) | {"details"}

    details: dict[str, Any] = {}
    if isinstance(payload.get("details"), dict):
        details.update(payload["details"])

    for key, value in payload.items():
        if key not in reserved_keys:
            details[key] = value

    row = AnomalyEvent(
        event_type=core.event_type,
        severity=core.severity.lower(),
        title=core.title,
        detected_at=core.detected_at,
        src_ip=core.src_ip,
        dst_ip=core.dst_ip,
        protocol=core.protocol.lower() if core.protocol else None,
        dst_port=core.dst_port,
        details=details,
    )

    with SessionLocal.begin() as session:
        session.add(row)
        session.flush()
        created_id = row.id

    return {"status": "saved", "id": str(created_id)}


@app.get("/dashboard/summary")
def get_dashboard_summary(minutes: int = 1):
    minutes = max(1, min(minutes, 10))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=minutes)
    events_cutoff = now - timedelta(minutes=LIVE_POLL_WINDOW_MINUTES)

    with SessionLocal() as session:
        observations = session.execute(
            select(TrafficObservation)
            .where(TrafficObservation.window_ts >= cutoff)
            .order_by(TrafficObservation.window_ts.asc())
        ).scalars().all()

        events = session.execute(
            select(AnomalyEvent)
            .where(AnomalyEvent.detected_at >= events_cutoff)
            .order_by(AnomalyEvent.detected_at.desc())
        ).scalars().all()

    active_flows = {
        (row.src_ip, row.dst_ip, row.protocol, row.dst_port)
        for row in observations
    }

    return {
        "window_minutes": minutes,
        "observation_count": len(observations),
        "active_flows": len(active_flows),
        "total_packet_rate": round(sum(row.packet_rate for row in observations), 3),
        "total_byte_count": int(sum(row.byte_count for row in observations)),
        "total_payload_bytes": int(sum(row.payload_bytes for row in observations)),
        "ml_anomaly_count": sum(1 for row in observations if row.ml_anomaly),
        "event_count_10m": len(events),
        "critical_count_10m": sum(1 for e in events if e.severity == "critical"),
        "warning_count_10m": sum(1 for e in events if e.severity == "warning"),
    }


@app.get("/dashboard/traffic-series")
def get_dashboard_traffic_series(minutes: int = 10):
    minutes = max(1, min(minutes, 10))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    with SessionLocal() as session:
        observations = session.execute(
            select(TrafficObservation)
            .where(TrafficObservation.window_ts >= cutoff)
            .order_by(TrafficObservation.window_ts.asc())
        ).scalars().all()

        events = session.execute(
            select(AnomalyEvent)
            .where(AnomalyEvent.detected_at >= cutoff)
            .order_by(AnomalyEvent.detected_at.asc())
        ).scalars().all()

    return {
        "window_minutes": minutes,
        "points": build_buckets(observations, events),
    }


@app.get("/dashboard/events")
def get_dashboard_events(limit: int = 30):
    limit = max(1, min(limit, 100))

    with SessionLocal() as session:
        events = session.execute(
            select(AnomalyEvent)
            .order_by(AnomalyEvent.detected_at.desc())
            .limit(limit)
        ).scalars().all()

    return [
        {
            "id": str(event.id),
            "event_type": event.event_type,
            "severity": event.severity,
            "title": event.title,
            "detected_at": to_utc_z(event.detected_at),
            "src_ip": str(event.src_ip) if event.src_ip else None,
            "dst_ip": str(event.dst_ip) if event.dst_ip else None,
            "protocol": event.protocol,
            "dst_port": event.dst_port,
            "details": event.details or {},
        }
        for event in events
    ]


@app.get("/dashboard/device-live/{device_name}")
def get_device_live(device_name: str, minutes: int = 5):
    minutes = max(1, min(minutes, 5))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    with SessionLocal() as session:
        device = session.execute(
            select(Device)
            .options(joinedload(Device.settings))
            .where(Device.name == device_name, Device.is_enabled.is_(True))
        ).scalar_one_or_none()

        if device is None:
            raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

        device_ip = str(device.ip_address)
        device_status = device.settings.status.value if device.settings else "unknown"

        if device.kind.value == "detector":
            detector_cutoff = datetime.now(timezone.utc) - timedelta(seconds=15)
            recent_observation = session.execute(
                select(TrafficObservation.id)
                .where(TrafficObservation.window_ts >= detector_cutoff)
                .limit(1)
            ).scalar_one_or_none()

            recent_event = session.execute(
                select(AnomalyEvent.id)
                .where(AnomalyEvent.detected_at >= detector_cutoff)
                .limit(1)
            ).scalar_one_or_none()

            device_status = "online" if (recent_observation or recent_event) else "offline"

        observations = session.execute(
            select(TrafficObservation)
            .where(
                TrafficObservation.window_ts >= cutoff,
                or_(
                    TrafficObservation.src_ip == device_ip,
                    TrafficObservation.dst_ip == device_ip,
                ),
            )
            .order_by(TrafficObservation.window_ts.asc())
        ).scalars().all()

        series_events = session.execute(
            select(AnomalyEvent)
            .where(
                AnomalyEvent.detected_at >= cutoff,
                or_(
                    AnomalyEvent.src_ip == device_ip,
                    AnomalyEvent.dst_ip == device_ip,
                ),
            )
            .order_by(AnomalyEvent.detected_at.asc())
        ).scalars().all()

        recent_events = session.execute(
            select(AnomalyEvent)
            .where(
                AnomalyEvent.detected_at >= cutoff,
                or_(
                    AnomalyEvent.src_ip == device_ip,
                    AnomalyEvent.dst_ip == device_ip,
                ),
            )
            .order_by(AnomalyEvent.detected_at.desc())
            .limit(20)
        ).scalars().all()

    return {
        "device": {
            "name": device.name,
            "ip_address": device_ip,
            "kind": device.kind.value,
            "status": device_status,
        },
        "window_minutes": minutes,
        "points": build_buckets(observations, series_events),
        "events": [
            {
                "id": str(event.id),
                "event_type": event.event_type,
                "severity": event.severity,
                "title": event.title,
                "detected_at": to_utc_z(event.detected_at),
                "src_ip": str(event.src_ip) if event.src_ip else None,
                "dst_ip": str(event.dst_ip) if event.dst_ip else None,
                "protocol": event.protocol,
                "dst_port": event.dst_port,
                "details": event.details or {},
            }
            for event in recent_events
        ],
    }