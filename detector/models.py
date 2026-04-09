from dataclasses import dataclass, field


@dataclass
class WindowStats:
    packet_count: int = 0
    byte_count: int = 0
    payload_bytes: int = 0
    arp_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    max_payload: int = 0
    iat_values: list[float] = field(default_factory=list)
    response_latencies_ms: list[float] = field(default_factory=list)