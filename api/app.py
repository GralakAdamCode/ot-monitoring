import os
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import joinedload, selectinload

from common.db import SessionLocal, wait_for_db
from common.models import (
    AnomalyEvent,
    AnomalyMode,
    Device,
    DeviceSettings,
    TrafficObservation,
)

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

app = FastAPI(title="OT Monitoring API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.on_event("startup")
def startup() -> None:
    wait_for_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/modes")
def get_modes():
    return [mode.value for mode in AnomalyMode]


@app.get("/devices")
def get_devices():
    with SessionLocal() as session:
        stmt = (
            select(Device)
            .options(joinedload(Device.settings), selectinload(Device.listen_ports))
            .where(Device.is_enabled.is_(True))
            .order_by(Device.name)
        )
        devices = session.execute(stmt).unique().scalars().all()

        result = []
        for device in devices:
            settings = device.settings
            result.append(
                {
                    "name": device.name,
                    "kind": device.kind.value,
                    "ip_address": str(device.ip_address),
                    "status": settings.status.value if settings else "unknown",
                    "anomaly_mode": settings.anomaly_mode.value if settings else "normal",
                    "anomaly_active": bool(settings.anomaly_active) if settings else False,
                    "bind_ip": str(settings.bind_ip) if settings and settings.bind_ip else None,
                    "bind_port": settings.bind_port if settings else None,
                    "target_ip": str(settings.target_ip) if settings and settings.target_ip else None,
                    "target_port": settings.target_port if settings else None,
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
            select(DeviceSettings)
            .join(Device, Device.id == DeviceSettings.device_id)
            .where(Device.name == device_name, Device.is_enabled.is_(True))
        )
        settings = session.execute(stmt).scalar_one_or_none()

        if settings is None:
            raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

        settings.anomaly_mode = new_mode
        settings.anomaly_active = new_mode != AnomalyMode.NORMAL

    return {
        "message": f"Ustawiono tryb {new_mode.value} dla {device_name}",
        "device_name": device_name,
        "mode": new_mode.value,
    }


@app.post("/detector/observations", status_code=status.HTTP_201_CREATED)
def create_detector_observation(payload: DetectorObservationIn):
    row = TrafficObservation(
        window_ts=payload.window_ts,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        protocol=payload.protocol.lower(),
        dst_port=payload.dst_port,
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