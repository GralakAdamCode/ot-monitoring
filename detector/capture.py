import time

from scapy.all import ARP, Ether, IP, Raw, TCP, UDP

from config import CONFIG
from rules.payload import maybe_emit_large_payload, maybe_emit_malformed_payload
from rules.topology import register_identity_and_topology
from state import (
    CURRENT_WINDOWS,
    LAST_PACKET_TS_BY_FLOW,
    PENDING_TCP_REQUESTS,
    RECENT_IATS_BY_FLOW,
    LOCK,
)


def parse_packet(pkt):
    if Ether not in pkt:
        return None

    ts = float(getattr(pkt, "time", time.time()))
    src_mac = pkt[Ether].src
    dst_mac = pkt[Ether].dst
    raw_payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    frame_len = len(bytes(pkt))
    payload_len = len(raw_payload)

    if ARP in pkt:
        arp = pkt[ARP]
        return {
            "ts": ts,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "protocol": "arp",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": "",
            "frame_len": frame_len,
            "payload_len": payload_len,
            "payload": raw_payload,
        }

    if IP not in pkt:
        return None

    ip = pkt[IP]
    info = {
        "ts": ts,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": "ip",
        "src_port": None,
        "dst_port": None,
        "tcp_flags": "",
        "frame_len": frame_len,
        "payload_len": payload_len,
        "payload": raw_payload,
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        info["protocol"] = "tcp"
        info["src_port"] = int(tcp.sport)
        info["dst_port"] = int(tcp.dport)
        info["tcp_flags"] = str(tcp.flags)
    elif UDP in pkt:
        udp = pkt[UDP]
        info["protocol"] = "udp"
        info["src_port"] = int(udp.sport)
        info["dst_port"] = int(udp.dport)

    return info


def prune_pending_requests(now_ts: float) -> None:
    cutoff = now_ts - CONFIG.request_timeout_seconds
    stale_keys = []

    for key, queue in PENDING_TCP_REQUESTS.items():
        while queue and queue[0] < cutoff:
            queue.popleft()
        if not queue:
            stale_keys.append(key)

    for key in stale_keys:
        PENDING_TCP_REQUESTS.pop(key, None)


def track_tcp_request_response(info: dict) -> tuple[tuple, float] | None:
    from utils import is_ephemeral_port

    if info["protocol"] != "tcp":
        return None
    if info["payload_len"] <= 0:
        return None
    if info["src_port"] is None or info["dst_port"] is None:
        return None

    prune_pending_requests(info["ts"])

    src_ip = info["src_ip"]
    dst_ip = info["dst_ip"]
    src_port = info["src_port"]
    dst_port = info["dst_port"]

    if is_ephemeral_port(src_port) and not is_ephemeral_port(dst_port):
        req_key = (src_ip, src_port, dst_ip, dst_port)
        queue = PENDING_TCP_REQUESTS[req_key]
        queue.append(info["ts"])
        while len(queue) > 20:
            queue.popleft()
        return None

    if not is_ephemeral_port(src_port) and is_ephemeral_port(dst_port):
        req_key = (dst_ip, dst_port, src_ip, src_port)
        queue = PENDING_TCP_REQUESTS.get(req_key)
        if queue:
            request_ts = queue.popleft()
            if not queue:
                PENDING_TCP_REQUESTS.pop(req_key, None)

            latency_ms = max(0.0, (info["ts"] - request_ts) * 1000.0)
            service_flow_key = (req_key[0], req_key[2], "tcp", req_key[3])
            return service_flow_key, latency_ms

    return None


def handle_packet(pkt) -> None:
    info = parse_packet(pkt)
    if info is None:
        return

    flow_key = (info["src_ip"], info["dst_ip"], info["protocol"], info["dst_port"])

    with LOCK:
        register_identity_and_topology(info)
        maybe_emit_large_payload(info)
        maybe_emit_malformed_payload(info)

        stats = CURRENT_WINDOWS[flow_key]
        stats.packet_count += 1
        stats.byte_count += info["frame_len"]
        stats.payload_bytes += info["payload_len"]
        stats.max_payload = max(stats.max_payload, info["payload_len"])

        if info["protocol"] == "arp":
            stats.arp_count += 1
        elif info["protocol"] == "tcp":
            stats.tcp_count += 1
            flags = info["tcp_flags"]
            if "S" in flags:
                stats.syn_count += 1
            if "R" in flags:
                stats.rst_count += 1
            if "F" in flags:
                stats.fin_count += 1
        elif info["protocol"] == "udp":
            stats.udp_count += 1

        previous_ts = LAST_PACKET_TS_BY_FLOW.get(flow_key)
        if previous_ts is not None:
            delta = max(0.0, info["ts"] - previous_ts)
            stats.iat_values.append(delta)
            RECENT_IATS_BY_FLOW[flow_key].append(delta)
        LAST_PACKET_TS_BY_FLOW[flow_key] = info["ts"]

        latency_result = track_tcp_request_response(info)
        if latency_result is not None:
            service_flow_key, latency_ms = latency_result
            CURRENT_WINDOWS[service_flow_key].response_latencies_ms.append(latency_ms)