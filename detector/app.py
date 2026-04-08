import json
import os
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import requests
from scapy.all import ARP, Ether, IP, Raw, TCP, UDP, get_if_list, sniff
from sklearn.ensemble import IsolationForest


MONITOR_IFACE = os.getenv("MONITOR_IFACE", "otbr0")
API_BASE_URL = os.getenv("API_BASE_URL", "").rstrip("/")
AGG_INTERVAL_SECONDS = float(os.getenv("AGG_INTERVAL_SECONDS", "1"))
WARMUP_SECONDS = int(os.getenv("WARMUP_SECONDS", "60"))
SILENCE_SECONDS = float(os.getenv("SILENCE_SECONDS", "10"))
BURST_MULTIPLIER = float(os.getenv("BURST_MULTIPLIER", "3.0"))
LARGE_PAYLOAD_THRESHOLD = int(os.getenv("LARGE_PAYLOAD_THRESHOLD", "256"))
JITTER_MULTIPLIER = float(os.getenv("JITTER_MULTIPLIER", "3.0"))
RST_STORM_THRESHOLD = int(os.getenv("RST_STORM_THRESHOLD", "3"))
DETECTOR_MODE = os.getenv("DETECTOR_MODE", "hybrid").strip().lower()
ENABLE_ML = os.getenv("ENABLE_ML", "false").strip().lower() == "true"

USE_RULES = DETECTOR_MODE in {"rules", "hybrid"}
USE_ML = DETECTOR_MODE in {"ml", "hybrid"} and ENABLE_ML

START_TS = time.time()
LOCK = threading.Lock()


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
    max_payload: int = 0
    iat_values: list[float] = field(default_factory=list)


CURRENT_WINDOWS = defaultdict(WindowStats)
LAST_PACKET_TS_BY_FLOW = {}
LAST_SEEN_BY_IP = {}
EXPECTED_IPS = set()
SILENT_IPS = set()

KNOWN_IP_TO_MAC = {}
KNOWN_PEERS = defaultdict(set)
KNOWN_ROUTES = defaultdict(set)

BASELINES = defaultdict(lambda: {
    "samples": 0,
    "packet_rate": 0.0,
    "avg_packet_size": 0.0,
    "avg_interarrival_ms": 0.0,
    "jitter_ms": 0.0,
})

RECENT_EVENT_CACHE = {}
TRAINING_VECTORS = deque(maxlen=5000)
IF_MODEL = None


def in_warmup() -> bool:
    return (time.time() - START_TS) < WARMUP_SECONDS


def wait_for_interface(iface: str) -> None:
    while iface not in get_if_list():
        print(f"[DETECTOR] czekam na interfejs {iface}...", flush=True)
        time.sleep(2)


def post_json(path: str, payload: dict) -> None:
    if not API_BASE_URL:
        return
    try:
        requests.post(f"{API_BASE_URL}{path}", json=payload, timeout=1.5)
    except Exception:
        pass


def should_emit_event(key: tuple, ttl_seconds: float = 5.0) -> bool:
    now = time.time()
    stale = [k for k, ts in RECENT_EVENT_CACHE.items() if (now - ts) > ttl_seconds]
    for k in stale:
        RECENT_EVENT_CACHE.pop(k, None)

    if key in RECENT_EVENT_CACHE:
        return False

    RECENT_EVENT_CACHE[key] = now
    return True


def emit_event(event_type: str, severity: str, title: str, data: dict) -> None:
    cache_key = (
        event_type,
        data.get("src_ip"),
        data.get("dst_ip"),
        data.get("protocol"),
        data.get("dst_port"),
    )
    if not should_emit_event(cache_key):
        return

    payload = {
        "event_type": event_type,
        "severity": severity,
        "title": title,
        "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **data,
    }
    print(json.dumps({"kind": "event", **payload}, ensure_ascii=False), flush=True)
    post_json("/detector/events", payload)


def emit_observation(payload: dict) -> None:
    print(json.dumps({"kind": "observation", **payload}, ensure_ascii=False), flush=True)
    post_json("/detector/observations", payload)


def update_ema(old: float, new: float, alpha: float = 0.2) -> float:
    return new if old == 0.0 else ((1 - alpha) * old + alpha * new)


def update_baseline(flow_key: tuple, obs: dict) -> None:
    baseline = BASELINES[flow_key]
    baseline["samples"] += 1
    baseline["packet_rate"] = update_ema(baseline["packet_rate"], obs["packet_rate"])
    baseline["avg_packet_size"] = update_ema(baseline["avg_packet_size"], obs["avg_packet_size"])
    baseline["avg_interarrival_ms"] = update_ema(baseline["avg_interarrival_ms"], obs["avg_interarrival_ms"])
    baseline["jitter_ms"] = update_ema(baseline["jitter_ms"], obs["jitter_ms"])


def vectorize(obs: dict) -> list[float]:
    return [
        obs["packet_rate"],
        obs["byte_count"],
        obs["avg_packet_size"],
        obs["avg_interarrival_ms"],
        obs["jitter_ms"],
        obs["payload_bytes"],
        obs["max_payload"],
        obs["tcp_syn_count"],
        obs["tcp_rst_count"],
        obs["arp_count"],
    ]


def maybe_fit_iforest() -> None:
    global IF_MODEL

    if not USE_ML or IF_MODEL is not None:
        return

    if len(TRAINING_VECTORS) < 60:
        return

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(list(TRAINING_VECTORS))
    IF_MODEL = model
    print("[DETECTOR] Isolation Forest wytrenowany", flush=True)


def parse_packet(pkt):
    if Ether not in pkt:
        return None

    ts = float(getattr(pkt, "time", time.time()))
    src_mac = pkt[Ether].src
    dst_mac = pkt[Ether].dst
    frame_len = len(bytes(pkt))
    payload_len = len(bytes(pkt[Raw].load)) if Raw in pkt else 0

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


def register_identity_and_topology(info: dict) -> None:
    warmup = in_warmup()
    src_ip = info["src_ip"]
    dst_ip = info["dst_ip"]
    src_mac = info["src_mac"]
    proto = info["protocol"]
    dst_port = info["dst_port"]

    if src_ip:
        LAST_SEEN_BY_IP[src_ip] = info["ts"]
        SILENT_IPS.discard(src_ip)

    if warmup and src_ip:
        EXPECTED_IPS.add(src_ip)

    if src_ip and src_ip not in KNOWN_IP_TO_MAC:
        KNOWN_IP_TO_MAC[src_ip] = src_mac
        if not warmup:
            emit_event(
                "new_ip_detected",
                "warning",
                f"Nowy adres IP wykryty: {src_ip}",
                {"src_ip": src_ip, "src_mac": src_mac},
            )
    elif src_ip and KNOWN_IP_TO_MAC[src_ip] != src_mac:
        emit_event(
            "ip_mac_changed",
            "critical",
            f"Zmiana mapowania IP/MAC dla {src_ip}",
            {"src_ip": src_ip, "old_mac": KNOWN_IP_TO_MAC[src_ip], "new_mac": src_mac},
        )
        KNOWN_IP_TO_MAC[src_ip] = src_mac

    if proto in {"tcp", "udp"} and src_ip and dst_ip:
        route = (dst_ip, proto, dst_port)

        if dst_ip not in KNOWN_PEERS[src_ip]:
            if not warmup and src_ip in EXPECTED_IPS:
                emit_event(
                    "new_peer_detected",
                    "warning",
                    f"Nowy peer dla {src_ip}: {dst_ip}",
                    {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto},
                )
            KNOWN_PEERS[src_ip].add(dst_ip)

        if route not in KNOWN_ROUTES[src_ip]:
            if not warmup and src_ip in EXPECTED_IPS:
                emit_event(
                    "new_port_detected",
                    "warning",
                    f"Nowy target/port dla {src_ip}: {dst_ip}:{dst_port}/{proto}",
                    {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": proto},
                )
            KNOWN_ROUTES[src_ip].add(route)

    if not warmup and info["payload_len"] > LARGE_PAYLOAD_THRESHOLD:
        emit_event(
            "large_payload",
            "warning",
            f"Duży payload: {info['payload_len']} B",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "payload_size": info["payload_len"],
            },
        )


def handle_packet(pkt) -> None:
    info = parse_packet(pkt)
    if info is None:
        return

    flow_key = (info["src_ip"], info["dst_ip"], info["protocol"], info["dst_port"])

    with LOCK:
        register_identity_and_topology(info)

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
        elif info["protocol"] == "udp":
            stats.udp_count += 1

        previous_ts = LAST_PACKET_TS_BY_FLOW.get(flow_key)
        if previous_ts is not None:
            stats.iat_values.append(info["ts"] - previous_ts)
        LAST_PACKET_TS_BY_FLOW[flow_key] = info["ts"]


def analyze_rules(flow_key: tuple, obs: dict) -> bool:
    if not USE_RULES:
        return False

    triggered = False
    baseline = BASELINES[flow_key]
    src_ip, dst_ip, protocol, dst_port = flow_key

    if baseline["samples"] >= 5:
        burst_threshold = max(5.0, baseline["packet_rate"] * BURST_MULTIPLIER)
        if obs["packet_rate"] > burst_threshold:
            emit_event(
                "burst_traffic",
                "warning",
                f"Nagły wzrost ruchu dla {src_ip} -> {dst_ip}",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "packet_rate": obs["packet_rate"],
                    "baseline_packet_rate": round(baseline["packet_rate"], 3),
                },
            )
            triggered = True

        jitter_threshold = max(50.0, baseline["jitter_ms"] * JITTER_MULTIPLIER)
        if obs["packet_count"] > 2 and obs["jitter_ms"] > jitter_threshold:
            emit_event(
                "high_jitter",
                "warning",
                f"Wysoki jitter dla {src_ip} -> {dst_ip}",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "jitter_ms": round(obs["jitter_ms"], 3),
                    "baseline_jitter_ms": round(baseline["jitter_ms"], 3),
                },
            )
            triggered = True

    if obs["tcp_rst_count"] >= RST_STORM_THRESHOLD:
        emit_event(
            "tcp_reset_storm",
            "critical",
            f"Wiele TCP RST dla {src_ip} -> {dst_ip}",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_rst_count": obs["tcp_rst_count"],
            },
        )
        triggered = True

    return triggered


def flush_loop() -> None:
    global CURRENT_WINDOWS

    while True:
        time.sleep(AGG_INTERVAL_SECONDS)

        with LOCK:
            windows_snapshot = CURRENT_WINDOWS
            CURRENT_WINDOWS = defaultdict(WindowStats)

        for flow_key, stats in windows_snapshot.items():
            avg_packet_size = stats.byte_count / stats.packet_count if stats.packet_count else 0.0
            avg_iat_ms = (
                statistics.mean(stats.iat_values) * 1000 if stats.iat_values else 0.0
            )
            jitter_ms = (
                statistics.pstdev(stats.iat_values) * 1000 if len(stats.iat_values) >= 2 else 0.0
            )

            src_ip, dst_ip, protocol, dst_port = flow_key
            observation = {
                "window_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "dst_port": dst_port,
                "packet_count": stats.packet_count,
                "packet_rate": round(stats.packet_count / AGG_INTERVAL_SECONDS, 3),
                "byte_count": stats.byte_count,
                "payload_bytes": stats.payload_bytes,
                "avg_packet_size": round(avg_packet_size, 3),
                "avg_interarrival_ms": round(avg_iat_ms, 3),
                "jitter_ms": round(jitter_ms, 3),
                "max_payload": stats.max_payload,
                "arp_count": stats.arp_count,
                "tcp_syn_count": stats.syn_count,
                "tcp_rst_count": stats.rst_count,
                "ml_anomaly": False,
                "ml_score": None,
            }

            vector = vectorize(observation)

            if in_warmup():
                TRAINING_VECTORS.append(vector)
                update_baseline(flow_key, observation)
                emit_observation(observation)
                continue

            maybe_fit_iforest()

            rule_hit = analyze_rules(flow_key, observation)

            if USE_ML and IF_MODEL is not None:
                score = float(IF_MODEL.score_samples([vector])[0])
                pred = int(IF_MODEL.predict([vector])[0])
                observation["ml_score"] = round(score, 6)
                observation["ml_anomaly"] = pred == -1

                if pred == -1:
                    emit_event(
                        "ml_isolation_forest",
                        "warning",
                        f"Isolation Forest oznaczył ruch jako anomalię: {src_ip} -> {dst_ip}",
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": protocol,
                            "ml_score": observation["ml_score"],
                        },
                    )

            emit_observation(observation)

            if not rule_hit and not observation["ml_anomaly"]:
                update_baseline(flow_key, observation)


def silence_loop() -> None:
    while True:
        time.sleep(1)

        if in_warmup():
            continue

        now = time.time()
        with LOCK:
            for ip in list(EXPECTED_IPS):
                last_seen = LAST_SEEN_BY_IP.get(ip)
                if last_seen is None:
                    continue

                delta = now - last_seen

                if delta > SILENCE_SECONDS and ip not in SILENT_IPS:
                    emit_event(
                        "unexpected_silence",
                        "warning",
                        f"Brak ruchu od {ip} przez {round(delta, 2)} s",
                        {"src_ip": ip, "silence_seconds": round(delta, 2)},
                    )
                    SILENT_IPS.add(ip)


def main() -> None:
    print(
        f"[DETECTOR] start iface={MONITOR_IFACE} "
        f"mode={DETECTOR_MODE} use_rules={USE_RULES} use_ml={USE_ML}",
        flush=True,
    )

    wait_for_interface(MONITOR_IFACE)

    threading.Thread(target=flush_loop, daemon=True).start()
    threading.Thread(target=silence_loop, daemon=True).start()

    sniff(
        iface=MONITOR_IFACE,
        prn=handle_packet,
        store=False,
        promisc=True,
    )


if __name__ == "__main__":
    main()