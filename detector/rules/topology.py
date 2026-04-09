from baselines import in_warmup
from emitter import emit_event
from config import CONFIG
from state import (
    EXPECTED_IPS,
    KNOWN_IP_TO_MAC,
    KNOWN_PEERS,
    KNOWN_ROUTES,
    LAST_SEEN_BY_IP,
    SILENT_IPS,
)
from utils import is_ephemeral_port


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

    if warmup and src_ip in CONFIG.managed_ips:
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
            {
                "src_ip": src_ip,
                "old_mac": KNOWN_IP_TO_MAC[src_ip],
                "new_mac": src_mac,
            },
        )
        KNOWN_IP_TO_MAC[src_ip] = src_mac

    if proto in {"tcp", "udp"} and src_ip and dst_ip:
        if dst_ip not in KNOWN_PEERS[src_ip]:
            if not warmup and src_ip in EXPECTED_IPS:
                emit_event(
                    "new_peer_detected",
                    "warning",
                    f"Nowy peer dla {src_ip}: {dst_ip}",
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": proto,
                    },
                )
            KNOWN_PEERS[src_ip].add(dst_ip)

        if dst_port is not None and not is_ephemeral_port(dst_port):
            route = (dst_ip, proto, dst_port)
            if route not in KNOWN_ROUTES[src_ip]:
                if not warmup and src_ip in EXPECTED_IPS:
                    emit_event(
                        "new_port_detected",
                        "warning",
                        f"Nowy target/port dla {src_ip}: {dst_ip}:{dst_port}/{proto}",
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": proto,
                        },
                    )
                KNOWN_ROUTES[src_ip].add(route)