import os
import socket
import threading
import time

from common.db import mark_device_status, wait_for_db
from common.models import DeviceStatus
from common.runtime import RuntimeConfig, load_runtime


DEVICE_NAME = os.getenv("DEVICE_NAME", "plc")

_config_lock = threading.Lock()
_current_config: RuntimeConfig | None = None


def set_config(cfg: RuntimeConfig) -> None:
    global _current_config
    with _config_lock:
        _current_config = cfg


def get_config() -> RuntimeConfig:
    with _config_lock:
        if _current_config is None:
            raise RuntimeError("Brak configu PLC")
        return _current_config


def decode_message(data: bytes) -> str:
    return data.decode(errors="ignore").replace("\x00", "").strip("X").strip()


def udp_listener(port: int) -> None:
    cfg = get_config()
    bind_ip = cfg.bind_ip or "0.0.0.0"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    sock.settimeout(1.0)

    print(f"[{DEVICE_NAME}][UDP] nasluch na {bind_ip}:{port}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception as exc:
            print(f"[{DEVICE_NAME}][UDP:{port}] blad: {exc}", flush=True)
            time.sleep(0.2)
            continue

        cfg = get_config()

        if cfg.should_silent():
            print(f"[{DEVICE_NAME}][UDP:{port}] silent -> ignoruje pakiet", flush=True)
            continue

        message = decode_message(data)
        print(f"[{DEVICE_NAME}][UDP:{port}] od {addr} -> {message}", flush=True)


def handle_tcp_client(conn: socket.socket, addr) -> None:
    print(f"[{DEVICE_NAME}][TCP] nowe polaczenie od {addr}", flush=True)

    try:
        while True:
            cfg = get_config()
            conn.settimeout(max(0.5, cfg.timeout_ms / 1000.0))

            data = conn.recv(4096)
            if not data:
                break

            if cfg.should_disconnect():
                print(f"[{DEVICE_NAME}][TCP] disconnect dla {addr}", flush=True)
                break

            if cfg.should_silent():
                print(f"[{DEVICE_NAME}][TCP] silent -> ignoruje request od {addr}", flush=True)
                continue

            message = decode_message(data)
            print(f"[{DEVICE_NAME}][TCP] od {addr} -> {message}", flush=True)

            if cfg.should_slow_response():
                delay = max(0.0, cfg.response_delay_ms / 1000.0)
                print(f"[{DEVICE_NAME}][TCP] slow_response {delay}s", flush=True)
                time.sleep(delay)

            if message.startswith("STATUS"):
                response_text = cfg.response_payload_ok
            else:
                response_text = cfg.response_payload_unknown

            response = cfg.format_payload(response_text)
            conn.sendall(response)
            print(f"[{DEVICE_NAME}][TCP] do {addr} <- {response!r}", flush=True)

    except Exception as exc:
        print(f"[{DEVICE_NAME}][TCP] blad klienta {addr}: {exc}", flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[{DEVICE_NAME}][TCP] rozlaczono {addr}", flush=True)


def tcp_server(port: int) -> None:
    cfg = get_config()
    bind_ip = cfg.bind_ip or "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, port))
    server.listen()
    server.settimeout(1.0)

    print(f"[{DEVICE_NAME}][TCP] nasluch na {bind_ip}:{port}", flush=True)

    while True:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except Exception as exc:
            print(f"[{DEVICE_NAME}][TCP] accept error: {exc}", flush=True)
            time.sleep(0.2)
            continue

        thread = threading.Thread(
            target=handle_tcp_client,
            args=(conn, addr),
            daemon=True,
        )
        thread.start()


def config_refresher() -> None:
    while True:
        try:
            cfg = load_runtime(DEVICE_NAME)
            set_config(cfg)
        except Exception as exc:
            print(f"[{DEVICE_NAME}] blad odswiezania configu: {exc}", flush=True)

        try:
            sleep_time = max(0.5, get_config().refresh_interval_ms / 1000.0)
        except Exception:
            sleep_time = 1.0

        time.sleep(sleep_time)


def main() -> None:
    wait_for_db()
    mark_device_status(DEVICE_NAME, DeviceStatus.ONLINE)

    initial_cfg = load_runtime(DEVICE_NAME)
    set_config(initial_cfg)

    threading.Thread(target=config_refresher, daemon=True).start()

    for port in initial_cfg.udp_listen_ports:
        threading.Thread(target=udp_listener, args=(port,), daemon=True).start()

    tcp_ports = initial_cfg.tcp_listen_ports or ([initial_cfg.bind_port] if initial_cfg.bind_port else [])
    for port in tcp_ports:
        threading.Thread(target=tcp_server, args=(port,), daemon=True).start()

    print(f"[{DEVICE_NAME}] start", flush=True)

    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()