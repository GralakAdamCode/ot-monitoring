import os
from dataclasses import dataclass


def _bool_env(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() == "true"


@dataclass(frozen=True, slots=True)
class Config:
    monitor_iface: str = os.getenv("MONITOR_IFACE", "otbr0")
    api_base_url: str = os.getenv("API_BASE_URL", "").rstrip("/")

    agg_interval_seconds: float = float(os.getenv("AGG_INTERVAL_SECONDS", "1"))
    warmup_seconds: int = int(os.getenv("WARMUP_SECONDS", "30"))
    silence_seconds: float = float(os.getenv("SILENCE_SECONDS", "10"))

    min_baseline_samples: int = int(os.getenv("MIN_BASELINE_SAMPLES", "5"))

    burst_multiplier: float = float(os.getenv("BURST_MULTIPLIER", "2.5"))
    min_burst_rate: float = float(os.getenv("MIN_BURST_RATE", "2.0"))
    burst_abs_delta: float = float(os.getenv("BURST_ABS_DELTA", "1.0"))

    large_payload_threshold: int = int(os.getenv("LARGE_PAYLOAD_THRESHOLD", "256"))

    jitter_multiplier: float = float(os.getenv("JITTER_MULTIPLIER", "3.0"))
    min_jitter_ms: float = float(os.getenv("MIN_JITTER_MS", "250.0"))
    jitter_abs_delta: float = float(os.getenv("JITTER_ABS_DELTA", "150.0"))
    recent_iat_window: int = int(os.getenv("RECENT_IAT_WINDOW", "8"))
    min_jitter_flow_samples: int = int(os.getenv("MIN_JITTER_FLOW_SAMPLES", "6"))

    rst_storm_threshold: int = int(os.getenv("RST_STORM_THRESHOLD", "3"))

    ephemeral_port_min: int = int(os.getenv("EPHEMERAL_PORT_MIN", "32768"))

    request_timeout_seconds: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10.0"))
    slow_response_multiplier: float = float(os.getenv("SLOW_RESPONSE_MULTIPLIER", "3.0"))
    min_slow_response_ms: float = float(os.getenv("MIN_SLOW_RESPONSE_MS", "800.0"))
    slow_response_abs_delta: float = float(os.getenv("SLOW_RESPONSE_ABS_DELTA", "250.0"))

    malformed_printable_ratio: float = float(os.getenv("MALFORMED_PRINTABLE_RATIO", "0.75"))
    malformed_min_payload: int = int(os.getenv("MALFORMED_MIN_PAYLOAD", "4"))

    plc_tcp_port: int = int(os.getenv("PLC_TCP_PORT", "15000"))

    detector_mode: str = os.getenv("DETECTOR_MODE", "hybrid").strip().lower()
    enable_ml: bool = _bool_env("ENABLE_ML", "false")

    @property
    def sensor_udp_ports(self) -> set[int]:
        raw = os.getenv("SENSOR_UDP_PORTS", "10001,10002,10003")
        return {int(part.strip()) for part in raw.split(",") if part.strip()}

    @property
    def managed_ips(self) -> set[str]:
        raw = os.getenv(
            "MANAGED_IPS",
            "172.28.0.10,172.28.0.20,172.28.0.31,172.28.0.32,172.28.0.33",
        )
        return {part.strip() for part in raw.split(",") if part.strip()}

    @property
    def use_rules(self) -> bool:
        return self.detector_mode in {"rules", "hybrid"}

    @property
    def use_ml(self) -> bool:
        return self.detector_mode in {"ml", "hybrid"} and self.enable_ml


CONFIG = Config()