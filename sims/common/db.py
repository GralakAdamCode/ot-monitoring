import os
import time
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, joinedload, selectinload

from common.models import Device, DeviceSettings, DeviceStatus


DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Brak DATABASE_URL")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)


def wait_for_db(retry_seconds: float = 2.0) -> None:
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(select(1))
            print("[DB] polaczono", flush=True)
            return
        except Exception as exc:
            print(f"[DB] czekam na baze: {exc}", flush=True)
            time.sleep(retry_seconds)


def mark_device_status(device_name: str, status: DeviceStatus) -> None:
    with SessionLocal.begin() as session:
        stmt = (
            select(DeviceSettings)
            .join(Device, Device.id == DeviceSettings.device_id)
            .where(Device.name == device_name)
        )
        settings = session.execute(stmt).scalar_one_or_none()
        if settings is None:
            raise RuntimeError(f"Nie znaleziono settings dla device={device_name}")
        settings.status = status


def load_device(device_name: str) -> Device:
    with SessionLocal() as session:
        stmt = (
            select(Device)
            .options(joinedload(Device.settings), selectinload(Device.listen_ports))
            .where(Device.name == device_name, Device.is_enabled.is_(True))
        )
        device = session.execute(stmt).unique().scalar_one_or_none()

        if device is None:
            raise RuntimeError(f"Nie znaleziono aktywnego urzadzenia: {device_name}")

        if device.settings is None:
            raise RuntimeError(f"Brak device_settings dla urzadzenia: {device_name}")

        return device