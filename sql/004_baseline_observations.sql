-- Baseline traffic observations for ML model training
-- These represent "normal" traffic patterns across different flows
-- The detector will learn from these during the warmup phase

BEGIN;

-- HMI → PLC control traffic (TCP port 15000)
-- Pattern: Regular status polling every 3 seconds, 1-2 packets per window, small payloads
INSERT INTO traffic_observations (
    window_ts, src_ip, dst_ip, protocol, dst_port,
    packet_count, packet_rate, byte_count, payload_bytes,
    avg_packet_size, avg_interarrival_ms, jitter_ms,
    max_payload, arp_count, tcp_syn_count, tcp_rst_count,
    ml_anomaly, ml_score
)
SELECT
    NOW() - INTERVAL '1 second' * generate_series(1, 120),
    '172.28.0.20'::inet,
    '172.28.0.10'::inet,
    'tcp',
    15000,
    CASE WHEN (generate_series(1, 120) % 3) = 0 THEN 1 ELSE 0 END::integer,
    CASE WHEN (generate_series(1, 120) % 3) = 0 THEN 0.33 ELSE 0.0 END::double precision,
    CASE WHEN (generate_series(1, 120) % 3) = 0 THEN 82 ELSE 0 END::integer,
    CASE WHEN (generate_series(1, 120) % 3) = 0 THEN 72 ELSE 0 END::integer,
    82.0::double precision,
    1050.0::double precision,
    45.5::double precision,
    72::integer,
    0::integer,
    CASE WHEN (generate_series(1, 120) % 3) = 0 THEN 1 ELSE 0 END::integer,
    0::integer,
    FALSE,
    0.015::double precision;

-- Sensor1 → PLC data (UDP port 10001)
-- Pattern: Regular sensor readings every second, 1 packet per window, consistent payload
INSERT INTO traffic_observations (
    window_ts, src_ip, dst_ip, protocol, dst_port,
    packet_count, packet_rate, byte_count, payload_bytes,
    avg_packet_size, avg_interarrival_ms, jitter_ms,
    max_payload, arp_count, tcp_syn_count, tcp_rst_count,
    ml_anomaly, ml_score
)
SELECT
    NOW() - INTERVAL '1 second' * generate_series(1, 120),
    '172.28.0.31'::inet,
    '172.28.0.10'::inet,
    'udp',
    10001,
    1::integer,
    1.0::double precision,
    96::integer,
    64::integer,
    96.0::double precision,
    985.0::double precision,
    32.0::double precision,
    64::integer,
    0::integer,
    0::integer,
    0::integer,
    FALSE,
    0.008::double precision;

-- Sensor2 → PLC data (UDP port 10002)
-- Pattern: Similar to Sensor1, regular sensor readings
INSERT INTO traffic_observations (
    window_ts, src_ip, dst_ip, protocol, dst_port,
    packet_count, packet_rate, byte_count, payload_bytes,
    avg_packet_size, avg_interarrival_ms, jitter_ms,
    max_payload, arp_count, tcp_syn_count, tcp_rst_count,
    ml_anomaly, ml_score
)
SELECT
    NOW() - INTERVAL '1 second' * generate_series(1, 120),
    '172.28.0.32'::inet,
    '172.28.0.10'::inet,
    'udp',
    10002,
    1::integer,
    1.0::double precision,
    96::integer,
    64::integer,
    96.0::double precision,
    975.0::double precision,
    28.5::double precision,
    64::integer,
    0::integer,
    0::integer,
    0::integer,
    FALSE,
    0.010::double precision;

-- Sensor3 → PLC data (UDP port 10003)
-- Pattern: Similar to Sensor1 & 2, regular sensor readings
INSERT INTO traffic_observations (
    window_ts, src_ip, dst_ip, protocol, dst_port,
    packet_count, packet_rate, byte_count, payload_bytes,
    avg_packet_size, avg_interarrival_ms, jitter_ms,
    max_payload, arp_count, tcp_syn_count, tcp_rst_count,
    ml_anomaly, ml_score
)
SELECT
    NOW() - INTERVAL '1 second' * generate_series(1, 120),
    '172.28.0.33'::inet,
    '172.28.0.10'::inet,
    'udp',
    10003,
    1::integer,
    1.0::double precision,
    96::integer,
    64::integer,
    96.0::double precision,
    992.0::double precision,
    35.2::double precision,
    64::integer,
    0::integer,
    0::integer,
    0::integer,
    FALSE,
    0.007::double precision;

-- PLC broadcast/ARP traffic
-- Pattern: Occasional ARP requests, maintains network visibility
INSERT INTO traffic_observations (
    window_ts, src_ip, dst_ip, protocol, dst_port,
    packet_count, packet_rate, byte_count, payload_bytes,
    avg_packet_size, avg_interarrival_ms, jitter_ms,
    max_payload, arp_count, tcp_syn_count, tcp_rst_count,
    ml_anomaly, ml_score
)
SELECT
    NOW() - INTERVAL '1 second' * generate_series(1, 120),
    '172.28.0.10'::inet,
    '255.255.255.255'::inet,
    'arp',
    NULL,
    CASE WHEN (generate_series(1, 120) % 5) = 0 THEN 1 ELSE 0 END::integer,
    CASE WHEN (generate_series(1, 120) % 5) = 0 THEN 0.2 ELSE 0.0 END::double precision,
    CASE WHEN (generate_series(1, 120) % 5) = 0 THEN 42 ELSE 0 END::integer,
    CASE WHEN (generate_series(1, 120) % 5) = 0 THEN 28 ELSE 0 END::integer,
    42.0::double precision,
    4950.0::double precision,
    150.0::double precision,
    28::integer,
    CASE WHEN (generate_series(1, 120) % 5) = 0 THEN 1 ELSE 0 END::integer,
    0::integer,
    0::integer,
    FALSE,
    0.012::double precision;

COMMIT;
