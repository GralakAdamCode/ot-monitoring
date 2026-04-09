from config import CONFIG


def is_ephemeral_port(port: int | None) -> bool:
    return port is not None and port >= CONFIG.ephemeral_port_min


def is_timing_flow(flow_key: tuple) -> bool:
    _, _, protocol, dst_port = flow_key

    if protocol == "udp" and dst_port in CONFIG.sensor_udp_ports:
        return True

    if protocol == "tcp" and dst_port == CONFIG.plc_tcp_port:
        return True

    return False


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0

    printable = 0
    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1
    return printable / len(data)


def safe_payload_preview(data: bytes, limit: int = 48) -> str:
    sample = data[:limit]
    try:
        text = sample.decode("utf-8", errors="ignore").replace("\x00", "").strip()
        if text:
            return text
    except Exception:
        pass
    return sample.hex()