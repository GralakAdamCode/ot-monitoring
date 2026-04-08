export type Device = {
  name: string;
  kind: string;
  ip_address: string;
  status: string;
  anomaly_mode: string;
  anomaly_active: boolean;
  bind_ip?: string | null;
  bind_port?: number | null;
  target_ip?: string | null;
  target_port?: number | null;
};

export type TrafficPoint = {
  ts: string;
  packet_rate_sum: number;
  byte_count_sum: number;
  payload_bytes_sum: number;
  avg_jitter_ms: number;
  max_payload: number;
  flow_count: number;
  ml_anomaly_count: number;
  event_count: number;
};

export type DashboardEvent = {
  id: string;
  event_type: string;
  severity: string;
  title: string;
  detected_at: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  protocol?: string | null;
  dst_port?: number | null;
  details?: Record<string, unknown>;
};

export type DeviceLiveResponse = {
  device: {
    name: string;
    ip_address: string;
    kind: string;
    status: string;
  };
  window_minutes: number;
  points: TrafficPoint[];
  events: DashboardEvent[];
};