from config import CONFIG
from emitter import emit_event


def analyze_session_rules(flow_key: tuple, obs: dict) -> bool:
    src_ip, dst_ip, protocol, dst_port = flow_key
    triggered = False

    if obs.get("tcp_rst_count", 0) >= CONFIG.rst_storm_threshold:
        emit_event(
            "tcp_reset_storm",
            "critical",
            f"Wiele TCP RST dla {src_ip} -> {dst_ip}",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_rst_count": obs.get("tcp_rst_count", 0),
            },
        )
        triggered = True

    if (
        protocol == "tcp"
        and obs.get("tcp_syn_count", 0) >= 1
        and obs.get("tcp_fin_count", 0) >= 1
    ):
        emit_event(
            "connection_churn",
            "warning",
            f"Krótka sesja TCP dla {src_ip} -> {dst_ip}",
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_syn_count": obs.get("tcp_syn_count", 0),
                "tcp_fin_count": obs.get("tcp_fin_count", 0),
            },
        )
        triggered = True

    return triggered