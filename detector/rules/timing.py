from config import CONFIG
from emitter import emit_event
from state import BASELINES
from utils import is_timing_flow


def analyze_timing_rules(flow_key: tuple, obs: dict) -> bool:
    src_ip, dst_ip, protocol, dst_port = flow_key

    if not is_timing_flow(flow_key):
        return False

    baseline = BASELINES[flow_key]
    if baseline["samples"] < CONFIG.min_baseline_samples:
        return False

    triggered = False

    base_rate = baseline["packet_rate"]
    burst_threshold = max(
        CONFIG.min_burst_rate,
        base_rate * CONFIG.burst_multiplier,
        base_rate + CONFIG.burst_abs_delta,
    )

    if obs["packet_rate"] >= burst_threshold and obs["packet_count"] >= 2:
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
                "baseline_packet_rate": round(base_rate, 3),
                "burst_threshold": round(burst_threshold, 3),
            },
        )
        triggered = True

    base_jitter = baseline["jitter_ms"]
    jitter_threshold = max(
        CONFIG.min_jitter_ms,
        base_jitter * CONFIG.jitter_multiplier,
        base_jitter + CONFIG.jitter_abs_delta,
    )

    if (
        obs.get("rolling_iat_samples", 0) >= CONFIG.min_jitter_flow_samples
        and obs["jitter_ms"] >= jitter_threshold
    ):
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
                "baseline_jitter_ms": round(base_jitter, 3),
                "jitter_threshold": round(jitter_threshold, 3),
            },
        )
        triggered = True

    avg_response_latency_ms = obs.get("avg_response_latency_ms")
    if avg_response_latency_ms is not None:
        base_resp = baseline.get("response_latency_ms", 0.0)
        slow_threshold = max(
            CONFIG.min_slow_response_ms,
            base_resp * CONFIG.slow_response_multiplier,
            base_resp + CONFIG.slow_response_abs_delta,
        )
        if avg_response_latency_ms >= slow_threshold:
            emit_event(
                "slow_response",
                "warning",
                f"Wolna odpowiedź TCP dla {src_ip} -> {dst_ip}",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "avg_response_latency_ms": round(avg_response_latency_ms, 3),
                    "baseline_response_latency_ms": round(base_resp, 3),
                    "slow_response_threshold_ms": round(slow_threshold, 3),
                },
            )
            triggered = True

    return triggered