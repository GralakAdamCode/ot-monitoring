from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import joinedload, selectinload

from common.db import SessionLocal, wait_for_db
from common.models import Device, DeviceSettings, AnomalyMode


app = FastAPI(title="OT Monitoring API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ModeChange(BaseModel):
    mode: str


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