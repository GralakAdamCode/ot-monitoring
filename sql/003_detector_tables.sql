CREATE TABLE IF NOT EXISTS traffic_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    window_ts TIMESTAMPTZ NOT NULL,

    src_ip INET,
    dst_ip INET,
    protocol VARCHAR(16) NOT NULL,
    dst_port INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 1 AND 65535),

    packet_count INTEGER NOT NULL CHECK (packet_count >= 0),
    packet_rate DOUBLE PRECISION NOT NULL CHECK (packet_rate >= 0),
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),

    avg_packet_size DOUBLE PRECISION NOT NULL CHECK (avg_packet_size >= 0),
    avg_interarrival_ms DOUBLE PRECISION NOT NULL CHECK (avg_interarrival_ms >= 0),
    jitter_ms DOUBLE PRECISION NOT NULL CHECK (jitter_ms >= 0),

    max_payload INTEGER NOT NULL CHECK (max_payload >= 0),
    arp_count INTEGER NOT NULL DEFAULT 0 CHECK (arp_count >= 0),
    tcp_syn_count INTEGER NOT NULL DEFAULT 0 CHECK (tcp_syn_count >= 0),
    tcp_rst_count INTEGER NOT NULL DEFAULT 0 CHECK (tcp_rst_count >= 0),

    ml_anomaly BOOLEAN NOT NULL DEFAULT FALSE,
    ml_score DOUBLE PRECISION,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traffic_observations_window_ts
    ON traffic_observations(window_ts DESC);

CREATE INDEX IF NOT EXISTS idx_traffic_observations_src_ip
    ON traffic_observations(src_ip);

CREATE INDEX IF NOT EXISTS idx_traffic_observations_dst_ip
    ON traffic_observations(dst_ip);

CREATE INDEX IF NOT EXISTS idx_traffic_observations_protocol_port
    ON traffic_observations(protocol, dst_port);


CREATE TABLE IF NOT EXISTS anomaly_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    title VARCHAR(255) NOT NULL,

    detected_at TIMESTAMPTZ NOT NULL,

    src_ip INET,
    dst_ip INET,
    protocol VARCHAR(16),
    dst_port INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 1 AND 65535),

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_detected_at
    ON anomaly_events(detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_event_type
    ON anomaly_events(event_type);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_severity
    ON anomaly_events(severity);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_src_ip
    ON anomaly_events(src_ip);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_dst_ip
    ON anomaly_events(dst_ip);