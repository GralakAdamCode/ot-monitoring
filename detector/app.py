import statistics
import threading
import time

from scapy.all import get_if_list, sniff

import state
from baselines import in_warmup, update_baseline
from capture import handle_packet
from config import CONFIG
from emitter import emit_observation
from rules.ml import analyze_ml, maybe_fit_iforest, vectorize
from rules.session import analyze_session_rules
from rules.silence import check_silence
from rules.timing import analyze_timing_rules


def wait_for_interface(iface: str) -> None:
    while iface not in get_if_list():
        print(f"[DETECTOR] czekam na interfejs {iface}...", flush=True)
        time.sleep(2)

def flush_loop() -> None:
    while True:
        time.sleep(CONFIG.agg_interval_seconds)

        with state.LOCK:
            windows_snapshot = dict(state.CURRENT_WINDOWS)
            state.CURRENT_WINDOWS.clear()

        for flow_key, stats in windows_snapshot.items():
            rolling_iats = list(state.RECENT_IATS_BY_FLOW.get(flow_key, []))

            avg_packet_size = stats.byte_count / stats.packet_count if stats.packet_count else 0.0
            avg_iat_ms = statistics.mean(rolling_iats) * 1000 if rolling_iats else 0.0
            jitter_ms = (
                statistics.pstdev(rolling_iats) * 1000 if len(rolling_iats) >= 2 else 0.0
            )
            avg_response_latency_ms = (
                statistics.mean(stats.response_latencies_ms)
                if stats.response_latencies_ms
                else None
            )

            src_ip, dst_ip, protocol, dst_port = flow_key
            observation = {
                "window_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "dst_port": dst_port,
                "packet_count": stats.packet_count,
                "packet_rate": round(stats.packet_count / CONFIG.agg_interval_seconds, 3),
                "byte_count": stats.byte_count,
                "payload_bytes": stats.payload_bytes,
                "avg_packet_size": round(avg_packet_size, 3),
                "avg_interarrival_ms": round(avg_iat_ms, 3),
                "jitter_ms": round(jitter_ms, 3),
                "max_payload": stats.max_payload,
                "arp_count": stats.arp_count,
                "tcp_syn_count": stats.syn_count,
                "tcp_rst_count": stats.rst_count,
                "tcp_fin_count": stats.fin_count,
                "rolling_iat_samples": len(rolling_iats),
                "avg_response_latency_ms": (
                    round(avg_response_latency_ms, 3)
                    if avg_response_latency_ms is not None
                    else None
                ),
                "ml_anomaly": False,
                "ml_score": None,
            }

            vector = vectorize(observation)

            if in_warmup():
                state.TRAINING_VECTORS.append(vector)
                update_baseline(flow_key, observation)
                emit_observation(observation)
                continue

            maybe_fit_iforest()

            rule_hit = False
            if CONFIG.use_rules:
                rule_hit = analyze_timing_rules(flow_key, observation)
                rule_hit = analyze_session_rules(flow_key, observation) or rule_hit

            ml_hit = analyze_ml(flow_key, observation)

            emit_observation(observation)

            if not rule_hit and not ml_hit:
                update_baseline(flow_key, observation)

def silence_loop() -> None:
    while True:
        time.sleep(1)
        with state.LOCK:
            check_silence()


def main() -> None:
    print(
        f"[DETECTOR] start iface={CONFIG.monitor_iface} "
        f"mode={CONFIG.detector_mode} use_rules={CONFIG.use_rules} use_ml={CONFIG.use_ml}",
        flush=True,
    )

    wait_for_interface(CONFIG.monitor_iface)

    threading.Thread(target=flush_loop, daemon=True).start()
    threading.Thread(target=silence_loop, daemon=True).start()

    sniff(
        iface=CONFIG.monitor_iface,
        prn=handle_packet,
        store=False,
        promisc=True,
    )


if __name__ == "__main__":
    main()