CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE device_kind AS ENUM (
    'plc',
    'hmi',
    'sensor',
    'detector',
    'rogue'
);

CREATE TYPE device_status AS ENUM (
    'unknown',
    'online',
    'offline'
);

CREATE TYPE anomaly_mode AS ENUM (
    'normal',
    'silent',
    'burst',
    'jitter',
    'large_payload',
    'new_port',
    'change_ip',
    'disconnect',
    'slow_response',
    'malformed_payload'
);

CREATE TYPE port_protocol AS ENUM (
    'udp',
    'tcp'
);

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    kind device_kind NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE device_settings (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,

    status device_status NOT NULL DEFAULT 'unknown',
    anomaly_mode anomaly_mode NOT NULL DEFAULT 'normal',
    anomaly_active BOOLEAN NOT NULL DEFAULT FALSE,

    refresh_interval_ms INTEGER NOT NULL DEFAULT 2000 CHECK (refresh_interval_ms > 0),

    bind_ip INET,
    bind_port INTEGER CHECK (bind_port BETWEEN 1 AND 65535),

    target_ip INET,
    target_port INTEGER CHECK (target_port BETWEEN 1 AND 65535),

    anomaly_ip INET,
    anomaly_port INTEGER CHECK (anomaly_port BETWEEN 1 AND 65535),

    normal_interval_ms INTEGER NOT NULL DEFAULT 1000 CHECK (normal_interval_ms > 0),
    burst_interval_ms INTEGER NOT NULL DEFAULT 200 CHECK (burst_interval_ms > 0),
    jitter_percent INTEGER NOT NULL DEFAULT 50 CHECK (jitter_percent BETWEEN 0 AND 1000),

    timeout_ms INTEGER NOT NULL DEFAULT 2000 CHECK (timeout_ms > 0),
    reconnect_delay_ms INTEGER NOT NULL DEFAULT 2000 CHECK (reconnect_delay_ms >= 0),

    payload_size INTEGER NOT NULL DEFAULT 64 CHECK (payload_size > 0),
    payload_pad INTEGER NOT NULL DEFAULT 256 CHECK (payload_pad >= 0),

    request_payload TEXT NOT NULL DEFAULT '',
    response_payload_ok TEXT NOT NULL DEFAULT 'OK\n',
    response_payload_unknown TEXT NOT NULL DEFAULT 'UNKNOWN\n',

    response_delay_ms INTEGER NOT NULL DEFAULT 0 CHECK (response_delay_ms >= 0),

    value_min DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    value_max DOUBLE PRECISION NOT NULL DEFAULT 100.0,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE device_listen_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol port_protocol NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, protocol, port)
);

CREATE INDEX idx_devices_kind ON devices(kind);
CREATE INDEX idx_devices_enabled ON devices(is_enabled);
CREATE INDEX idx_device_listen_ports_device_id ON device_listen_ports(device_id);