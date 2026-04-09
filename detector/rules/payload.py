from baselines import in_warmup
from config import CONFIG
from emitter import emit_event
from utils import printable_ratio, safe_payload_preview


def looks_malformed_payload(info: dict) -> bool:
    data = info["payload"]
    if len(data) < CONFIG.malformed_min_payload:
        return False

    text = data.decode("utf-8", errors="ignore").replace("\x00", "")
    normalized = text.strip().strip("X")
    ratio = printable_ratio(data)

    if b"\x00" in data or b"\xff" in data:
        return True

    if info["protocol"] == "udp" and info["dst_port"] in CONFIG.sensor_udp_ports:
        return "|seq=" not in text or "|value=" not in text

    if info["protocol"] == "tcp" and info["dst_port"] == CONFIG.plc_tcp_port:
        return not normalized.startswith("STATUS")

    if info["protocol"] == "tcp" and info["src_port"] == CONFIG.plc_tcp_port:
        return not (normalized.startswith("OK") or normalized.startswith("UNKNOWN"))

    return ratio < CONFIG.malformed_printable_ratio


def maybe_emit_malformed_payload(info: dict) -> None:
    if in_warmup():
        return
    if info["payload_len"] <= 0:
        return
    if not looks_malformed_payload(info):
        return

    emit_event(
        "malformed_payload",
        "warning",
        f"Podejrzany payload dla {info['src_ip']} -> {info['dst_ip']}",
        {
            "src_ip": info["src_ip"],
            "dst_ip": info["dst_ip"],
            "dst_port": info["dst_port"],
            "protocol": info["protocol"],
            "payload_size": info["payload_len"],
            "payload_preview": safe_payload_preview(info["payload"]),
        },
    )


def maybe_emit_large_payload(info: dict) -> None:
    if in_warmup():
        return
    if info["payload_len"] <= CONFIG.large_payload_threshold:
        return

    emit_event(
        "large_payload",
        "warning",
        f"Duży payload: {info['payload_len']} B",
        {
            "src_ip": info["src_ip"],
            "dst_ip": info["dst_ip"],
            "dst_port": info["dst_port"],
            "protocol": info["protocol"],
            "payload_size": info["payload_len"],
        },
    )