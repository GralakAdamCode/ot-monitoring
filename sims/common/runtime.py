import random
from dataclasses import dataclass
from typing import List

from common.db import load_device
from common.models import AnomalyMode, DeviceKind, DeviceStatus, PortProtocol


@dataclass(slots=True)
class RuntimeConfig:
    name: str
    kind: DeviceKind
    ip_address: str
    status: DeviceStatus

    anomaly_mode: AnomalyMode
    anomaly_active: bool

    refresh_interval_ms: int

    bind_ip: str | None
    bind_port: int | None

    target_ip: str | None
    target_port: int | None

    anomaly_ip: str | None
    anomaly_port: int | None

    normal_interval_ms: int
    burst_interval_ms: int
    jitter_percent: int

    timeout_ms: int
    reconnect_delay_ms: int

    payload_size: int
    payload_pad: int

    request_payload: str
    response_payload_ok: str
    response_payload_unknown: str

    response_delay_ms: int

    value_min: float
    value_max: float

    udp_listen_ports: List[int]
    tcp_listen_ports: List[int]

    def anomaly_enabled(self, mode: AnomalyMode) -> bool:
        return self.anomaly_active and self.anomaly_mode == mode

    def should_silent(self) -> bool:
        return self.anomaly_enabled(AnomalyMode.SILENT)

    def should_disconnect(self) -> bool:
        return self.anomaly_enabled(AnomalyMode.DISCONNECT)

    def should_slow_response(self) -> bool:
        return self.anomaly_enabled(AnomalyMode.SLOW_RESPONSE)

    def resolved_target_ip(self) -> str | None:
        if self.anomaly_enabled(AnomalyMode.CHANGE_IP) and self.anomaly_ip:
            return self.anomaly_ip
        return self.target_ip

    def resolved_target_port(self) -> int | None:
        if self.anomaly_enabled(AnomalyMode.NEW_PORT) and self.anomaly_port:
            return self.anomaly_port
        return self.target_port

    def resolved_interval_seconds(self) -> float:
        if self.anomaly_enabled(AnomalyMode.BURST):
            return max(0.05, self.burst_interval_ms / 1000.0)

        if self.anomaly_enabled(AnomalyMode.JITTER):
            base = max(50, self.normal_interval_ms)
            delta = max(1, int(base * (self.jitter_percent / 100.0)))
            low = max(50, base - delta)
            high = max(low, base + delta)
            return random.randint(low, high) / 1000.0

        return max(0.05, self.normal_interval_ms / 1000.0)

    def format_payload(self, text: str) -> bytes:
        if self.anomaly_enabled(AnomalyMode.MALFORMED_PAYLOAD):
            return b"\x00\xffBROKEN\x10\x11"

        raw = text.encode("utf-8", errors="ignore")

        if self.anomaly_enabled(AnomalyMode.LARGE_PAYLOAD):
            target_size = len(raw) + self.payload_pad
            raw += b"X" * max(0, target_size - len(raw))

        return raw

def load_runtime(device_name: str) -> RuntimeConfig:
    device = load_device(device_name)
    settings = device.settings

    udp_ports = sorted(
        port.port
        for port in device.listen_ports
        if port.is_enabled and port.protocol == PortProtocol.UDP
    )
    tcp_ports = sorted(
        port.port
        for port in device.listen_ports
        if port.is_enabled and port.protocol == PortProtocol.TCP
    )

    if settings.bind_port and settings.bind_port not in tcp_ports:
        tcp_ports.append(settings.bind_port)

    return RuntimeConfig(
        name=device.name,
        kind=device.kind,
        ip_address=str(device.ip_address),
        status=settings.status,
        anomaly_mode=settings.anomaly_mode,
        anomaly_active=settings.anomaly_active,
        refresh_interval_ms=settings.refresh_interval_ms,
        bind_ip=str(settings.bind_ip) if settings.bind_ip else None,
        bind_port=settings.bind_port,
        target_ip=str(settings.target_ip) if settings.target_ip else None,
        target_port=settings.target_port,
        anomaly_ip=str(settings.anomaly_ip) if settings.anomaly_ip else None,
        anomaly_port=settings.anomaly_port,
        normal_interval_ms=settings.normal_interval_ms,
        burst_interval_ms=settings.burst_interval_ms,
        jitter_percent=settings.jitter_percent,
        timeout_ms=settings.timeout_ms,
        reconnect_delay_ms=settings.reconnect_delay_ms,
        payload_size=settings.payload_size,
        payload_pad=settings.payload_pad,
        request_payload=settings.request_payload,
        response_payload_ok=settings.response_payload_ok,
        response_payload_unknown=settings.response_payload_unknown,
        response_delay_ms=settings.response_delay_ms,
        value_min=settings.value_min,
        value_max=settings.value_max,
        udp_listen_ports=udp_ports,
        tcp_listen_ports=tcp_ports,
    )