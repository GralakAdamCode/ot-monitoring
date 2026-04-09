from sklearn.ensemble import IsolationForest

from config import CONFIG
from emitter import emit_event
import state


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
        obs.get("avg_response_latency_ms") or 0.0,
    ]


def maybe_fit_iforest() -> None:
    if not CONFIG.use_ml or state.IF_MODEL is not None:
        return

    if len(state.TRAINING_VECTORS) < 80:
        return

    model = IsolationForest(
        n_estimators=120,
        contamination=0.05,
        random_state=42,
    )
    model.fit(list(state.TRAINING_VECTORS))
    state.IF_MODEL = model
    print("[DETECTOR] Isolation Forest wytrenowany", flush=True)


def analyze_ml(flow_key: tuple, obs: dict) -> bool:
    if not CONFIG.use_ml or state.IF_MODEL is None:
        return False

    src_ip, dst_ip, protocol, dst_port = flow_key
    vector = vectorize(obs)

    score = float(state.IF_MODEL.score_samples([vector])[0])
    pred = int(state.IF_MODEL.predict([vector])[0])

    obs["ml_score"] = round(score, 6)
    obs["ml_anomaly"] = pred == -1

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
                "ml_score": obs["ml_score"],
            },
        )
        return True

    return False