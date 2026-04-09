import json
import time

import requests

from config import CONFIG
from state import RECENT_EVENT_CACHE


OBSERVATION_POST_KEYS = {
    "window_ts",
    "src_ip",
    "dst_ip",
    "protocol",
    "dst_port",
    "packet_count",
    "packet_rate",
    "byte_count",
    "payload_bytes",
    "avg_packet_size",
    "avg_interarrival_ms",
    "jitter_ms",
    "max_payload",
    "arp_count",
    "tcp_syn_count",
    "tcp_rst_count",
    "ml_anomaly",
    "ml_score",
}


def post_json(path: str, payload: dict) -> None:
    if not CONFIG.api_base_url:
        print(f"[DETECTOR] API_BASE_URL puste, pomijam POST {path}", flush=True)
        return

    response = None
    try:
        response = requests.post(
            f"{CONFIG.api_base_url}{path}",
            json=payload,
            timeout=2.0,
        )
        response.raise_for_status()
    except Exception as exc:
        body = ""
        if response is not None:
            try:
                body = response.text[:500]
            except Exception:
                body = ""
        print(
            f"[DETECTOR] POST {path} failed: {exc}; response={body}; payload={json.dumps(payload, ensure_ascii=False)}",
            flush=True,
        )


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
    public_payload = {key: payload[key] for key in OBSERVATION_POST_KEYS}
    print(json.dumps({"kind": "observation", **public_payload}, ensure_ascii=False), flush=True)
    post_json("/detector/observations", public_payload)