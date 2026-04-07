import enum
import uuid
from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    return [member.value for member in enum_cls]


def pg_enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(
        enum_cls,
        name=name,
        values_callable=enum_values,
        native_enum=True,
        validate_strings=True,
    )


class DeviceKind(str, enum.Enum):
    PLC = "plc"
    HMI = "hmi"
    SENSOR = "sensor"
    DETECTOR = "detector"
    ROGUE = "rogue"


class DeviceStatus(str, enum.Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"


class AnomalyMode(str, enum.Enum):
    NORMAL = "normal"
    SILENT = "silent"
    BURST = "burst"
    JITTER = "jitter"
    LARGE_PAYLOAD = "large_payload"
    NEW_PORT = "new_port"
    CHANGE_IP = "change_ip"
    DISCONNECT = "disconnect"
    SLOW_RESPONSE = "slow_response"
    MALFORMED_PAYLOAD = "malformed_payload"


class PortProtocol(str, enum.Enum):
    UDP = "udp"
    TCP = "tcp"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    kind: Mapped[DeviceKind] = mapped_column(
        pg_enum(DeviceKind, "device_kind"),
        nullable=False,
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    settings: Mapped["DeviceSettings"] = relationship(
        back_populates="device",
        uselist=False,
        lazy="joined",
    )
    listen_ports: Mapped[list["DeviceListenPort"]] = relationship(
        back_populates="device",
        lazy="selectin",
    )


class DeviceSettings(Base):
    __tablename__ = "device_settings"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        primary_key=True,
    )

    status: Mapped[DeviceStatus] = mapped_column(
        pg_enum(DeviceStatus, "device_status"),
        nullable=False,
        default=DeviceStatus.UNKNOWN,
        server_default=text("'unknown'"),
    )

    anomaly_mode: Mapped[AnomalyMode] = mapped_column(
        pg_enum(AnomalyMode, "anomaly_mode"),
        nullable=False,
        default=AnomalyMode.NORMAL,
        server_default=text("'normal'"),
    )

    anomaly_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    refresh_interval_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=2000)

    bind_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    bind_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    target_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    anomaly_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    anomaly_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    normal_interval_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    burst_interval_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=200)
    jitter_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    timeout_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=2000)
    reconnect_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=2000)

    payload_size: Mapped[int] = mapped_column(Integer, nullable=False, default=64)
    payload_pad: Mapped[int] = mapped_column(Integer, nullable=False, default=256)

    request_payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response_payload_ok: Mapped[str] = mapped_column(Text, nullable=False, default="OK\n")
    response_payload_unknown: Mapped[str] = mapped_column(Text, nullable=False, default="UNKNOWN\n")

    response_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    value_min: Mapped[float] = mapped_column(nullable=False, default=0.0)
    value_max: Mapped[float] = mapped_column(nullable=False, default=100.0)

    device: Mapped["Device"] = relationship(back_populates="settings")


class DeviceListenPort(Base):
    __tablename__ = "device_listen_ports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    protocol: Mapped[PortProtocol] = mapped_column(
        pg_enum(PortProtocol, "port_protocol"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    device: Mapped["Device"] = relationship(back_populates="listen_ports")

class TrafficObservation(Base):
    __tablename__ = "traffic_observations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    window_ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)

    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_rate: Mapped[float] = mapped_column(Float, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    avg_packet_size: Mapped[float] = mapped_column(Float, nullable=False)
    avg_interarrival_ms: Mapped[float] = mapped_column(Float, nullable=False)
    jitter_ms: Mapped[float] = mapped_column(Float, nullable=False)

    max_payload: Mapped[int] = mapped_column(Integer, nullable=False)
    arp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    tcp_syn_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    tcp_rst_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))

    ml_anomaly: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    detected_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)

    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )