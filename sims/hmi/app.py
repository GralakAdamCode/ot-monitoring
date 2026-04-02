import os
import socket
import time

from common.db import mark_device_status, wait_for_db
from common.models import DeviceStatus
from common.runtime import load_runtime


DEVICE_NAME = os.getenv("DEVICE_NAME", "hmi")


def close_socket(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def main() -> None:
    wait_for_db()
    mark_device_status(DEVICE_NAME, DeviceStatus.ONLINE)

    sock: socket.socket | None = None
    connected_to: tuple[str, int] | None = None

    cfg = load_runtime(DEVICE_NAME)
    last_refresh = 0.0

    print(f"[{DEVICE_NAME}] start", flush=True)

    while True:
        try:
            now = time.monotonic()
            if now - last_refresh >= max(0.5, cfg.refresh_interval_ms / 1000.0):
                cfg = load_runtime(DEVICE_NAME)
                last_refresh = now

            if cfg.should_silent():
                if sock is not None:
                    close_socket(sock)
                    sock = None
                    connected_to = None
                print(f"[{DEVICE_NAME}] tryb silent", flush=True)
                time.sleep(0.2)
                continue

            target_ip = cfg.resolved_target_ip()
            target_port = cfg.resolved_target_port()

            if not target_ip or not target_port:
                print(f"[{DEVICE_NAME}] brak target_ip/target_port", flush=True)
                time.sleep(1.0)
                continue

            if sock is None or connected_to != (target_ip, target_port):
                close_socket(sock)

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(cfg.timeout_ms / 1000.0)
                sock.connect((target_ip, target_port))
                connected_to = (target_ip, target_port)

                print(
                    f"[{DEVICE_NAME}] polaczono -> {target_ip}:{target_port}",
                    flush=True,
                )

            payload_text = cfg.request_payload or "STATUS\n"
            payload = cfg.format_payload(payload_text)

            sock.sendall(payload)
            print(
                f"[{DEVICE_NAME}] wyslano -> {target_ip}:{target_port} | {payload!r}",
                flush=True,
            )

            if cfg.should_disconnect():
                print(f"[{DEVICE_NAME}] anomalia disconnect", flush=True)
                close_socket(sock)
                sock = None
                connected_to = None
                time.sleep(cfg.resolved_interval_seconds())
                continue

            response = sock.recv(4096)
            print(f"[{DEVICE_NAME}] odpowiedz <- {response!r}", flush=True)

            time.sleep(cfg.resolved_interval_seconds())

        except Exception as exc:
            print(f"[{DEVICE_NAME}] blad: {exc}", flush=True)
            close_socket(sock)
            sock = None
            connected_to = None
            time.sleep(max(0.2, cfg.reconnect_delay_ms / 1000.0))


if __name__ == "__main__":
    main()