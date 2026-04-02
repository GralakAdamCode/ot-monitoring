INSERT INTO devices (name, kind, ip_address) VALUES
    ('plc', 'plc', '172.28.0.10'),
    ('hmi', 'hmi', '172.28.0.20'),
    ('sensor1', 'sensor', '172.28.0.31'),
    ('sensor2', 'sensor', '172.28.0.32'),
    ('sensor3', 'sensor', '172.28.0.33'),
    ('detector', 'detector', '172.28.0.100')
ON CONFLICT (name) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    bind_ip,
    bind_port,
    anomaly_port,
    payload_size,
    response_payload_ok,
    response_payload_unknown,
    response_delay_ms,
    timeout_ms,
    reconnect_delay_ms
)
SELECT
    id,
    '0.0.0.0',
    15000,
    16000,
    64,
    'OK\n',
    'UNKNOWN\n',
    2000,
    2000,
    2000
FROM devices
WHERE name = 'plc'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    target_ip,
    target_port,
    anomaly_ip,
    anomaly_port,
    normal_interval_ms,
    burst_interval_ms,
    jitter_percent,
    timeout_ms,
    reconnect_delay_ms,
    payload_size,
    payload_pad,
    request_payload
)
SELECT
    id,
    '172.28.0.10',
    15000,
    '172.28.0.99',
    16000,
    3000,
    500,
    50,
    2000,
    2000,
    16,
    256,
    'STATUS\n'
FROM devices
WHERE name = 'hmi'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    target_ip,
    target_port,
    anomaly_ip,
    anomaly_port,
    normal_interval_ms,
    burst_interval_ms,
    jitter_percent,
    timeout_ms,
    reconnect_delay_ms,
    payload_size,
    payload_pad,
    value_min,
    value_max
)
SELECT
    id,
    '172.28.0.10',
    10001,
    '172.28.0.99',
    11001,
    1000,
    200,
    50,
    2000,
    2000,
    64,
    256,
    20.0,
    30.0
FROM devices
WHERE name = 'sensor1'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    target_ip,
    target_port,
    anomaly_ip,
    anomaly_port,
    normal_interval_ms,
    burst_interval_ms,
    jitter_percent,
    timeout_ms,
    reconnect_delay_ms,
    payload_size,
    payload_pad,
    value_min,
    value_max
)
SELECT
    id,
    '172.28.0.10',
    10002,
    '172.28.0.99',
    11002,
    1000,
    200,
    50,
    2000,
    2000,
    64,
    256,
    20.0,
    30.0
FROM devices
WHERE name = 'sensor2'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    target_ip,
    target_port,
    anomaly_ip,
    anomaly_port,
    normal_interval_ms,
    burst_interval_ms,
    jitter_percent,
    timeout_ms,
    reconnect_delay_ms,
    payload_size,
    payload_pad,
    value_min,
    value_max
)
SELECT
    id,
    '172.28.0.10',
    10003,
    '172.28.0.99',
    11003,
    1000,
    200,
    50,
    2000,
    2000,
    64,
    256,
    20.0,
    30.0
FROM devices
WHERE name = 'sensor3'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_settings (
    device_id,
    normal_interval_ms
)
SELECT
    id,
    5000
FROM devices
WHERE name = 'detector'
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO device_listen_ports (device_id, protocol, port)
SELECT id, 'udp', 10001 FROM devices WHERE name = 'plc'
ON CONFLICT (device_id, protocol, port) DO NOTHING;

INSERT INTO device_listen_ports (device_id, protocol, port)
SELECT id, 'udp', 10002 FROM devices WHERE name = 'plc'
ON CONFLICT (device_id, protocol, port) DO NOTHING;

INSERT INTO device_listen_ports (device_id, protocol, port)
SELECT id, 'udp', 10003 FROM devices WHERE name = 'plc'
ON CONFLICT (device_id, protocol, port) DO NOTHING;

INSERT INTO device_listen_ports (device_id, protocol, port)
SELECT id, 'tcp', 15000 FROM devices WHERE name = 'plc'
ON CONFLICT (device_id, protocol, port) DO NOTHING;