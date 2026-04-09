import time

from config import CONFIG
from state import BASELINES, START_TS


def in_warmup() -> bool:
    return (time.time() - START_TS) < CONFIG.warmup_seconds


def update_ema(old: float, new: float, alpha: float = 0.2) -> float:
    return new if old == 0.0 else ((1 - alpha) * old + alpha * new)


def update_baseline(flow_key: tuple, obs: dict) -> None:
    baseline = BASELINES[flow_key]
    baseline["samples"] += 1
    baseline["packet_rate"] = update_ema(baseline["packet_rate"], obs["packet_rate"])
    baseline["avg_packet_size"] = update_ema(baseline["avg_packet_size"], obs["avg_packet_size"])
    baseline["avg_interarrival_ms"] = update_ema(
        baseline["avg_interarrival_ms"], obs["avg_interarrival_ms"]
    )
    baseline["jitter_ms"] = update_ema(baseline["jitter_ms"], obs["jitter_ms"])

    if obs.get("avg_response_latency_ms") is not None:
        baseline["response_latency_ms"] = update_ema(
            baseline["response_latency_ms"],
            obs["avg_response_latency_ms"],
        )