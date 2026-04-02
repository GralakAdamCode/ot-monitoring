import os
import random
import socket
import time

from common.db import mark_device_status, wait_for_db
from common.models import DeviceStatus
from common.runtime import load_runtime


DEVICE_NAME = os.getenv("DEVICE_NAME", "sensor")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def main() -> None:
    wait_for_db()
    mark_device_status(DEVICE_NAME, DeviceStatus.ONLINE)

    cfg = load_runtime(DEVICE_NAME)
    last_refresh = 0.0
    seq = 0

    print(f"[{DEVICE_NAME}] start", flush=True)

    while True:
        try:
            now = time.monotonic()
            if now - last_refresh >= max(0.5, cfg.refresh_interval_ms / 1000.0):
                cfg = load_runtime(DEVICE_NAME)
                last_refresh = now

            if cfg.should_silent():
                print(f"[{DEVICE_NAME}] tryb silent", flush=True)
                time.sleep(0.2)
                continue

            target_ip = cfg.resolved_target_ip()
            target_port = cfg.resolved_target_port()

            if not target_ip or not target_port:
                print(f"[{DEVICE_NAME}] brak target_ip/target_port", flush=True)
                time.sleep(1.0)
                continue

            seq += 1
            value = random.uniform(min(cfg.value_min, cfg.value_max), max(cfg.value_min, cfg.value_max))

            payload_text = f"{DEVICE_NAME}|seq={seq}|value={value:.3f}"
            payload = cfg.format_payload(payload_text)

            sock.sendto(payload, (target_ip, target_port))

            print(
                f"[{DEVICE_NAME}] -> {target_ip}:{target_port} | {payload!r}",
                flush=True,
            )

            if cfg.should_disconnect():
                print(f"[{DEVICE_NAME}] anomalia disconnect -> pomijam kolejny cykl", flush=True)
                time.sleep(cfg.resolved_interval_seconds())
                continue

            time.sleep(cfg.resolved_interval_seconds())

        except Exception as exc:
            print(f"[{DEVICE_NAME}] blad: {exc}", flush=True)
            time.sleep(max(0.2, cfg.reconnect_delay_ms / 1000.0))


if __name__ == "__main__":
    main()