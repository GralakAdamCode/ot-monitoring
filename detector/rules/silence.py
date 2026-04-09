import time

from baselines import in_warmup
from emitter import emit_event
from config import CONFIG
from state import EXPECTED_IPS, LAST_SEEN_BY_IP, SILENT_IPS


def check_silence() -> None:
    if in_warmup():
        return

    now = time.time()
    for ip in list(EXPECTED_IPS):
        last_seen = LAST_SEEN_BY_IP.get(ip)
        if last_seen is None:
            continue

        delta = now - last_seen
        if delta > CONFIG.silence_seconds and ip not in SILENT_IPS:
            emit_event(
                "unexpected_silence",
                "warning",
                f"Brak ruchu od {ip} przez {round(delta, 2)} s",
                {
                    "src_ip": ip,
                    "silence_seconds": round(delta, 2),
                },
            )
            SILENT_IPS.add(ip)