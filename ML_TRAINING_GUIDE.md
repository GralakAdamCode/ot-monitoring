# ML Training Setup Guide

## Overview

This setup enables the **IsolationForest ML model** to learn what "normal" traffic looks like in your OT network. The model is trained on baseline observations during the detector's **warmup phase** (default: 30 seconds).

## Architecture

```
Device Traffic (Simulators)
        ↓
  Detector (Scapy)
        ↓
 Observations Collected
        ↓
  During Warmup:
  • Rule-based analysis runs
  • Observations added to TRAINING_VECTORS
  • After 80+ samples → IsolationForest model trains
        ↓
  After Warmup:
  • ML scores all new observations
  • Flags anomalies (prediction == -1)
        ↓
  API Storage → Database → Frontend Visualization
```

## Database Setup

### 1. SQL Migration Files

Three SQL files manage the database:

- **`001_schema.sql`** – Creates tables (devices, device_settings, device_listen_ports, traffic_observations, anomaly_events)
- **`002_seed.sql`** – Populates devices and device configurations
- **`003_detector_tables.sql`** – Creates detector-specific tables
- **`004_baseline_observations.sql`** – Pre-populates realistic "normal" traffic patterns (NEW)

### 2. Running Migrations

Migrations run automatically on database startup via Docker:

```bash
# In docker-compose.yaml, postgres service has:
volumes:
  - ./sql:/docker-entrypoint-initdb.d:ro
```

Files execute in alphabetical order:
1. `001_schema.sql` creates structure
2. `002_seed.sql` seeds devices & configs
3. `003_detector_tables.sql` creates anomaly tracking
4. `004_baseline_observations.sql` populates baseline traffic (optional)

## Baseline Data Generation

### Option A: Use SQL Pre-Population (Fastest)

The `004_baseline_observations.sql` file automatically inserts 600+ baseline observations representing "normal" traffic:

```bash
# Run the system - migrations execute automatically
docker compose up

# After DB initializes, you have:
# - 120 HMI → PLC observations
# - 120 Sensor1 → PLC observations
# - 120 Sensor2 → PLC observations
# - 120 Sensor3 → PLC observations
# - 120 PLC ARP observations
```

**Pros:**
- No external dependencies
- Guaranteed consistency
- Reproducible

**Cons:**
- Fixed patterns (less variation)
- Requires SQL regeneration for changes

### Option B: Use Python Generator Script (Flexible)

Generate synthetic observations with customizable parameters:

```bash
# Build detector image (includes generate_baseline.py)
docker build -f sims/hmi/Dockerfile -t py311-base .

# Generate observations (from host)
python3 scripts/generate_baseline.py \
  --count=200 \
  --hours=4.0 \
  --clear

# Output:
# ✓ Connected to database
# Generating 200 observations per flow...
#   ✓ HMI → PLC (TCP:15000): 67 observations
#   ✓ Sensor1 → PLC (UDP:10001): 200 observations
#   ✓ Sensor2 → PLC (UDP:10002): 200 observations
#   ✓ Sensor3 → PLC (UDP:10003): 200 observations
#   ✓ PLC ARP broadcast: 40 observations
# 
# 📊 Flow Statistics:
# 172.28.0.20     → 172.28.0.10     tcp 15000        |  67 obs | rate: 0.33 p/s | IAT: 1056ms
# 172.28.0.31     → 172.28.0.10     udp 10001        | 200 obs | rate: 1.00 p/s | IAT: 993ms
# 172.28.0.32     → 172.28.0.10     udp 10002        | 200 obs | rate: 1.00 p/s | IAT: 977ms
# 172.28.0.33     → 172.28.0.10     udp 10003        | 200 obs | rate: 1.00 p/s | IAT: 993ms
# 172.28.0.10     → 255.255.255.255  arp (broadcast)  |  40 obs | rate: 0.20 p/s | IAT: 5019ms
```

**Pros:**
- Customizable patterns and timing
- Can include realistic variations (jitter, timing drift)
- Good for testing different scenarios

**Cons:**
- Requires database connectivity
- External Python dependency
- More complex to integrate in CI/CD

## Configuration

### Enable ML Detection

Set environment variables in `.env`:

```bash
# Enable ML model training and detection
ENABLE_ML=true
DETECTOR_MODE=hybrid  # or "ml" for ML-only, "rules" for rules-only

# Optional: Configure warmup period (seconds to establish baseline)
WARMUP_SECONDS=30

# Optional: Adjust model parameters (in detector/rules/ml.py)
# n_estimators=120           # Number of trees in forest
# contamination=0.05         # Expected anomaly rate in baseline
# random_state=42            # For reproducibility
```

### Device Configuration

All devices configured in `002_seed.sql`:

| Device | IP | Port | Mode | Role |
|--------|----|----|------|------|
| PLC | 172.28.0.10 | 15000 (TCP), 10001-3 (UDP) | Listener | Control hub |
| HMI | 172.28.0.20 | N/A | Client | Polls PLC |
| Sensor1-3 | 172.28.0.31-33 | UDP ports | Clients | Send readings |
| Detector | 172.28.0.100 | Network | Monitor | Packet capture |

## ML Training Process

### Sequence:

1. **System Startup**
   - Detector connects to network interface
   - Starts capturing packets
   - Begins 30-second warmup phase

2. **Warmup Phase (First 30 seconds)**
   - Simulators send normal traffic
   - Detector calculates observations
   - Observations added to `TRAINING_VECTORS` deque (maxlen=5000)
   - **After 80+ vectors:** `maybe_fit_iforest()` triggers training

3. **Model Training** (automatic, ~100ms)
   - IsolationForest fits on training vectors
   - Model stored in `state.IF_MODEL`
   - Print: `"[DETECTOR] Isolation Forest wytrenowany"`

4. **Live Detection** (after warmup)
   - New observations scored with ML model
   - Score appended: `obs["ml_score"]` 
   - Anomaly flag set: `obs["ml_anomaly"] = (prediction == -1)`
   - If anomalous → emit event

### Feature Vector (11 dimensions):

```python
[
    packet_rate,              # packets per second
    byte_count,               # total bytes in window
    avg_packet_size,          # bytes per packet
    avg_interarrival_ms,      # inter-arrival time in ms
    jitter_ms,                # timing variation
    payload_bytes,            # application data
    max_payload,              # largest single payload
    tcp_syn_count,            # TCP connection attempts
    tcp_rst_count,            # TCP resets
    arp_count,                # ARP requests
    avg_response_latency_ms,  # request-response delay (or 0.0)
]
```

## Testing ML Model

### 1. Verify Setup

```bash
# Check if ML is enabled in logs
docker compose logs detector | grep "use_ml"
# Output: "mode=hybrid use_rules=True use_ml=True"

# Watch model training
docker compose logs -f detector | grep "wytrenowany"
# Output: "[DETECTOR] Isolation Forest wytrenowany"
```

### 2. Trigger Anomalies

Use the API to change device settings and trigger anomalies:

```bash
# Get detector device ID
curl http://localhost:8000/devices | jq '.[] | select(.name=="detector")'

# Trigger BURST anomaly
curl -X PATCH http://localhost:8000/devices/{id} \
  -H "Content-Type: application/json" \
  -d '{"anomaly_mode":"burst","anomaly_active":true}'

# Check anomaly events
curl http://localhost:8000/anomalies | jq '.' | grep ml_isolation_forest

# Output: "ml_isolation_forest" events with ml_score values
```

### 3. Monitor Dashboard

- Frontend shows real-time observations with ML scores
- Anomaly timeline displays ML-detected events
- Charts color-code normal vs. ML-detected anomalies

## Data Flow Example

### Normal Traffic (HMI → PLC)

```
Device sends:    request → PLC every 3 seconds
Detector sees:   packet_rate=0.33, avg_iat=1050ms, jitter=45ms
Observation:     {packet_rate: 0.33, jitter_ms: 45, ...}
ML vectorizes:   [0.33, 82, 82.0, 1050.0, 45.0, 72, 72, 1, 0, 0, 0.0]
Model predicts:  +1 (normal) → ml_anomaly=false, ml_score≈0.015
Result:          No alert
```

### Anomalous Traffic (Burst)

```
Device sends:    10 requests in 1 second (100x rate!)
Detector sees:   packet_rate=10.0, avg_iat=100ms, jitter=500ms
Observation:     {packet_rate: 10.0, jitter_ms: 500, ...}
ML vectorizes:   [10.0, 820, 82.0, 100.0, 500.0, 72, 72, 10, 0, 0, 0.0]
Model predicts:  -1 (anomaly!) → ml_anomaly=true, ml_score≈-0.8
Result:          Alert emitted: "ml_isolation_forest" event
```

## Troubleshooting

### Model Not Training

**Problem:** Detector logs don't show "Isolation Forest wytrenowany"

**Check:**
```bash
# 1. Is ML enabled?
grep ENABLE_ML .env

# 2. Is warmup running?
docker compose logs detector | grep "warmup\|Isolation"

# 3. Are observations being collected?
psql -h localhost -U otuser -d otmonitor -c \
  "SELECT COUNT(*) FROM traffic_observations;"
# Should be > 80
```

### Wrong Model Predictions

**Problem:** Normal traffic flagged as anomalies, or anomalies not detected

**Cause:** Baseline data doesn't match actual traffic patterns

**Fix:**
1. Review baseline observations:
   ```sql
   SELECT * FROM traffic_observations LIMIT 20 \gx
   ```

2. Compare with live observations:
   ```bash
   docker compose logs detector | grep "observation:"
   ```

3. Regenerate baseline with correct patterns:
   ```bash
   python3 scripts/generate_baseline.py --clear --count=200 --hours=4.0
   ```

4. Restart detector:
   ```bash
   docker compose restart detector
   ```

### Performance Issues

**Problem:** Detector using high CPU during ML training

**Normal:** Model training uses ~100ms of CPU (single-threaded)

**Optimize:**
- Reduce `n_estimators` in [detector/rules/ml.py](../detector/rules/ml.py#L14)
- Increase `contamination` if too many false positives
- Reduce TRAINING_VECTORS maxlen in [detector/state.py](../detector/state.py#L39)

## Next Steps

1. ✅ Enable ML: Set `ENABLE_ML=true` in `.env`
2. ✅ Start system: `docker compose up`
3. ✅ Wait for warmup (30 sec) + training (~1 sec)
4. ✅ Trigger test anomalies via API
5. ✅ Monitor dashboard for ML scores
6. ✅ Review anomaly events in database

## References

- [Scikit-learn IsolationForest Documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [detector/rules/ml.py](../detector/rules/ml.py) – ML implementation
- [detector/baselines.py](../detector/baselines.py) – Baseline management
- [sql/004_baseline_observations.sql](../sql/004_baseline_observations.sql) – Baseline data
- [scripts/generate_baseline.py](../scripts/generate_baseline.py) – Baseline generator

