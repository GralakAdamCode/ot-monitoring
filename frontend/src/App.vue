<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
} from "chart.js";
import { Line } from "vue-chartjs";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

type Device = {
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

type TrafficPoint = {
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

type DashboardEvent = {
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

type DeviceLiveResponse = {
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

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const devices = ref<Device[]>([]);
const modes = ref<string[]>([]);
const loading = ref(false);
const savingDevice = ref<string | null>(null);
const error = ref<string | null>(null);
const selectedModes = ref<Record<string, string>>({});

const liveModalOpen = ref(false);
const liveLoading = ref(false);
const liveDeviceName = ref<string | null>(null);
const liveDeviceData = ref<DeviceLiveResponse | null>(null);

let devicesInterval: number | undefined;
let liveInterval: number | undefined;

const totalDevices = computed(() => devices.value.length);
const onlineDevices = computed(
  () => devices.value.filter((d) => d.status === "online").length
);
const activeAnomalies = computed(
  () => devices.value.filter((d) => d.anomaly_active).length
);

function formatTs(ts: string) {
  return new Date(ts).toLocaleTimeString("pl-PL", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  plugins: {
    legend: {
      labels: {
        color: "#cbd5e1"
      }
    }
  },
  scales: {
    x: {
      ticks: {
        color: "#94a3b8",
        maxTicksLimit: 8,
        autoSkip: true
      },
      grid: { color: "rgba(148, 163, 184, 0.08)" }
    },
    y: {
      ticks: { color: "#94a3b8" },
      grid: { color: "rgba(148, 163, 184, 0.08)" }
    }
  }
};

const livePacketRateChartData = computed(() => ({
  labels: (liveDeviceData.value?.points ?? []).map((p) => formatTs(p.ts)),
  datasets: [
    {
      label: "Suma packet_rate",
      data: (liveDeviceData.value?.points ?? []).map((p) => p.packet_rate_sum),
      borderColor: "#60a5fa",
      backgroundColor: "rgba(96, 165, 250, 0.18)",
      fill: true,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    }
  ]
}));

const liveByteCountChartData = computed(() => ({
  labels: (liveDeviceData.value?.points ?? []).map((p) => formatTs(p.ts)),
  datasets: [
    {
      label: "Byte count",
      data: (liveDeviceData.value?.points ?? []).map((p) => p.byte_count_sum),
      borderColor: "#34d399",
      backgroundColor: "rgba(52, 211, 153, 0.18)",
      fill: true,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    }
  ]
}));

const liveJitterChartData = computed(() => ({
  labels: (liveDeviceData.value?.points ?? []).map((p) => formatTs(p.ts)),
  datasets: [
    {
      label: "Średni jitter [ms]",
      data: (liveDeviceData.value?.points ?? []).map((p) => p.avg_jitter_ms),
      borderColor: "#f59e0b",
      backgroundColor: "rgba(245, 158, 11, 0.18)",
      fill: true,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    }
  ]
}));

const liveAnomalyChartData = computed(() => ({
  labels: (liveDeviceData.value?.points ?? []).map((p) => formatTs(p.ts)),
  datasets: [
    {
      label: "ML anomalies",
      data: (liveDeviceData.value?.points ?? []).map((p) => p.ml_anomaly_count),
      borderColor: "rgba(239, 68, 68, 0.9)",
      backgroundColor: "rgba(239, 68, 68, 0.18)",
      fill: false,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    },
    {
      label: "Eventy",
      data: (liveDeviceData.value?.points ?? []).map((p) => p.event_count),
      borderColor: "rgba(168, 85, 247, 0.9)",
      backgroundColor: "rgba(168, 85, 247, 0.18)",
      fill: false,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    }
  ]
}));

async function loadData() {
  loading.value = true;
  error.value = null;

  try {
    const [devicesRes, modesRes] = await Promise.all([
      fetch(`${API_BASE}/devices`),
      fetch(`${API_BASE}/modes`)
    ]);

    if (!devicesRes.ok) throw new Error("Nie udało się pobrać urządzeń");
    if (!modesRes.ok) throw new Error("Nie udało się pobrać trybów");

    const devicesData: Device[] = await devicesRes.json();
    const modesData: string[] = await modesRes.json();

    devices.value = devicesData;
    modes.value = modesData;

    const nextSelected: Record<string, string> = {};
    for (const device of devicesData) {
      nextSelected[device.name] = device.anomaly_mode;
    }
    selectedModes.value = nextSelected;
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Nieznany błąd";
  } finally {
    loading.value = false;
  }
}

async function saveMode(deviceName: string) {
  const mode = selectedModes.value[deviceName];
  if (!mode) return;

  savingDevice.value = deviceName;
  error.value = null;

  try {
    const res = await fetch(`${API_BASE}/devices/${deviceName}/mode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ mode })
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || "Nie udało się zapisać trybu");
    }

    await loadData();
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Nieznany błąd";
  } finally {
    savingDevice.value = null;
  }
}

async function loadDeviceLive() {
  if (!liveDeviceName.value) return;

  liveLoading.value = true;

  try {
    const res = await fetch(
      `${API_BASE}/dashboard/device-live/${liveDeviceName.value}?minutes=5`
    );

    if (!res.ok) {
      throw new Error("Nie udało się pobrać danych live urządzenia");
    }

    liveDeviceData.value = await res.json();
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Nieznany błąd";
  } finally {
    liveLoading.value = false;
  }
}

async function openDeviceLive(deviceName: string) {
  liveDeviceName.value = deviceName;
  liveModalOpen.value = true;
  await loadDeviceLive();

  if (liveInterval) {
    window.clearInterval(liveInterval);
  }

  liveInterval = window.setInterval(loadDeviceLive, 3000);
}

function closeDeviceLive() {
  liveModalOpen.value = false;
  liveDeviceName.value = null;
  liveDeviceData.value = null;

  if (liveInterval) {
    window.clearInterval(liveInterval);
    liveInterval = undefined;
  }
}

function statusClass(status: string) {
  if (status === "online") return "badge badge--online";
  if (status === "offline") return "badge badge--offline";
  return "badge badge--unknown";
}

function severityClass(severity: string) {
  if (severity === "critical") return "event-card event-card--critical";
  if (severity === "warning") return "event-card event-card--warning";
  return "event-card";
}

onMounted(async () => {
  await loadData();
  devicesInterval = window.setInterval(loadData, 10000);
});

onBeforeUnmount(() => {
  if (devicesInterval) window.clearInterval(devicesInterval);
  if (liveInterval) window.clearInterval(liveInterval);
});
</script>

<template>
  <div class="app-shell">
    <header class="hero">
      <div class="hero__content">
        <p class="hero__eyebrow">OT MONITORING</p>
        <h1 class="hero__title">Panel sterowania środowiskiem</h1>
        <p class="hero__subtitle">
          Kliknij kafelek urządzenia, aby zobaczyć live view dla wybranego elementu.
        </p>
      </div>

      <div class="stats-grid">
        <article class="stat-card">
          <span class="stat-card__label">Urządzenia</span>
          <strong class="stat-card__value">{{ totalDevices }}</strong>
        </article>
        <article class="stat-card">
          <span class="stat-card__label">Online</span>
          <strong class="stat-card__value">{{ onlineDevices }}</strong>
        </article>
        <article class="stat-card">
          <span class="stat-card__label">Aktywne anomalie</span>
          <strong class="stat-card__value">{{ activeAnomalies }}</strong>
        </article>
      </div>
    </header>

    <section class="toolbar">
      <div>
        <h2 class="section-title">Urządzenia</h2>
        <p class="section-subtitle">
          Zmieniaj tryby i obserwuj stan symulowanych elementów.
        </p>
      </div>

      <button class="btn btn--secondary" @click="loadData" :disabled="loading">
        <span>Odśwież urządzenia</span>
        <span v-if="loading" class="btn__spinner"></span>
      </button>
    </section>

    <div v-if="error" class="error-box">
      {{ error }}
    </div>

    <main class="device-grid">
      <article
        v-for="device in devices"
        :key="device.name"
        class="device-card device-card--interactive"
        @click="openDeviceLive(device.name)"
      >
        <div class="device-card__header">
          <div>
            <h3 class="device-card__title">{{ device.name }}</h3>
            <div class="device-card__badges">
              <span class="badge badge--kind">{{ device.kind }}</span>
              <span :class="statusClass(device.status)">
                {{ device.status }}
              </span>
            </div>
          </div>

          <span
            class="mode-pill"
            :class="{ 'mode-pill--alert': device.anomaly_active }"
          >
            {{ device.anomaly_mode }}
          </span>
        </div>

        <div class="device-card__body">
          <div class="kv-row">
            <span class="kv-row__label">IP</span>
            <span class="kv-row__value">{{ device.ip_address }}</span>
          </div>

          <div class="kv-row">
            <span class="kv-row__label">Bind</span>
            <span class="kv-row__value">
              {{ device.bind_ip ?? "-" }}:{{ device.bind_port ?? "-" }}
            </span>
          </div>

          <div class="kv-row">
            <span class="kv-row__label">Target</span>
            <span class="kv-row__value">
              {{ device.target_ip ?? "-" }}:{{ device.target_port ?? "-" }}
            </span>
          </div>
        </div>

        <div class="device-card__footer" @click.stop>
          <select class="select" v-model="selectedModes[device.name]">
            <option v-for="mode in modes" :key="mode" :value="mode">
              {{ mode }}
            </option>
          </select>

          <button
            class="btn btn--primary"
            @click.stop="saveMode(device.name)"
            :disabled="savingDevice === device.name"
          >
            <span>Zapisz</span>
            <span v-if="savingDevice === device.name" class="btn__spinner"></span>
          </button>
        </div>

        <p class="device-card__hint">Kliknij kartę, aby otworzyć Show live</p>
      </article>
    </main>

    <div v-if="liveModalOpen" class="modal-backdrop" @click="closeDeviceLive">
      <div class="modal-card" @click.stop>
        <div class="modal-card__header">
          <div>
            <p class="hero__eyebrow">SHOW LIVE</p>
            <h2 class="section-title">
              {{ liveDeviceData?.device.name ?? liveDeviceName }}
            </h2>
            <p class="section-subtitle" v-if="liveDeviceData">
              {{ liveDeviceData.device.kind }} · {{ liveDeviceData.device.ip_address }} ·
              ostatnie {{ liveDeviceData.window_minutes }} minut
            </p>
          </div>

          <div class="modal-card__actions">
            <button class="btn btn--secondary" @click="loadDeviceLive" :disabled="liveLoading">
              <span>Odśwież live</span>
              <span v-if="liveLoading" class="btn__spinner"></span>
            </button>
            <button class="btn btn--secondary" @click="closeDeviceLive">
              Zamknij
            </button>
          </div>
        </div>

        <div v-if="liveDeviceData" class="charts-grid">
          <article class="chart-card">
            <div class="chart-card__header">
              <h3>Ruch pakietów</h3>
              <p>Suma packet_rate z ostatnich 5 minut</p>
            </div>
            <div class="chart-wrap">
              <Line :data="livePacketRateChartData" :options="chartOptions" />
            </div>
          </article>

          <article class="chart-card">
            <div class="chart-card__header">
              <h3>Byte count</h3>
              <p>Wolumen ruchu w czasie</p>
            </div>
            <div class="chart-wrap">
              <Line :data="liveByteCountChartData" :options="chartOptions" />
            </div>
          </article>

          <article class="chart-card">
            <div class="chart-card__header">
              <h3>Jitter</h3>
              <p>Średni jitter w oknach czasowych</p>
            </div>
            <div class="chart-wrap">
              <Line :data="liveJitterChartData" :options="chartOptions" />
            </div>
          </article>

          <article class="chart-card">
            <div class="chart-card__header">
              <h3>Anomalie i eventy</h3>
              <p>ML + rule-based zdarzenia</p>
            </div>
            <div class="chart-wrap">
              <Line :data="liveAnomalyChartData" :options="chartOptions" />
            </div>
          </article>
        </div>

        <section v-if="liveDeviceData" class="events-section">
          <div class="section-head">
            <div>
              <h2 class="section-title">Ostatnie eventy</h2>
              <p class="section-subtitle">
                Feed najnowszych anomalii i zdarzeń dla wybranego urządzenia.
              </p>
            </div>
          </div>

          <div class="events-list">
            <article
              v-for="event in liveDeviceData.events"
              :key="event.id"
              :class="severityClass(event.severity)"
            >
              <div class="event-card__top">
                <div>
                  <h3 class="event-card__title">{{ event.title }}</h3>
                  <p class="event-card__meta">
                    {{ formatTs(event.detected_at) }} · {{ event.event_type }} · {{ event.severity }}
                  </p>
                </div>
                <span class="mode-pill" :class="{ 'mode-pill--alert': event.severity !== 'info' }">
                  {{ event.severity }}
                </span>
              </div>

              <div class="event-card__body">
                <div class="kv-row">
                  <span class="kv-row__label">Źródło</span>
                  <span class="kv-row__value">{{ event.src_ip ?? "-" }}</span>
                </div>

                <div class="kv-row">
                  <span class="kv-row__label">Cel</span>
                  <span class="kv-row__value">
                    {{ event.dst_ip ?? "-" }}:{{ event.dst_port ?? "-" }}
                  </span>
                </div>

                <div class="kv-row">
                  <span class="kv-row__label">Protokół</span>
                  <span class="kv-row__value">{{ event.protocol ?? "-" }}</span>
                </div>
              </div>
            </article>

            <div v-if="liveDeviceData.events.length === 0" class="empty-box">
              Brak eventów do wyświetlenia.
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<style>
:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  line-height: 1.5;
  font-weight: 400;

  --border: rgba(148, 163, 184, 0.14);
  --text: #e5e7eb;
  --muted: #94a3b8;
  --accent: #60a5fa;
  --shadow: 0 20px 45px rgba(0, 0, 0, 0.3);

  background:
    radial-gradient(circle at top left, rgba(59, 130, 246, 0.18), transparent 30%),
    radial-gradient(circle at top right, rgba(99, 102, 241, 0.14), transparent 24%),
    linear-gradient(180deg, #070b14 0%, #0b1120 100%);
  color: var(--text);
}

* {
  box-sizing: border-box;
}

html,
body,
#app {
  margin: 0;
  min-height: 100%;
}

body {
  min-width: 320px;
  color: var(--text);
}

button,
select {
  font: inherit;
}

.app-shell {
  max-width: 1280px;
  margin: 0 auto;
  padding: 40px 20px 56px;
}

.hero {
  display: grid;
  gap: 22px;
  margin-bottom: 28px;
}

.hero__eyebrow {
  margin: 0 0 10px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.hero__title {
  margin: 0;
  font-size: clamp(30px, 4vw, 44px);
  line-height: 1.06;
  letter-spacing: -0.03em;
}

.hero__subtitle {
  margin: 14px 0 0;
  max-width: 760px;
  color: var(--muted);
  font-size: 15px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.stat-card {
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(17, 24, 39, 0.96), rgba(15, 23, 42, 0.88));
  box-shadow: var(--shadow);
}

.stat-card__label {
  display: block;
  margin-bottom: 8px;
  color: var(--muted);
  font-size: 13px;
}

.stat-card__value {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: -0.03em;
}

.toolbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.section-title {
  margin: 0;
  font-size: 20px;
}

.section-subtitle {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 14px;
}

.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
  gap: 16px;
}

.device-card {
  display: flex;
  flex-direction: column;
  gap: 18px;
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 18px;
  background: linear-gradient(180deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.86));
  box-shadow: var(--shadow);
}

.device-card--interactive {
  cursor: pointer;
  transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
}

.device-card--interactive:hover {
  transform: translateY(-2px);
  border-color: rgba(96, 165, 250, 0.26);
  box-shadow: 0 24px 55px rgba(0, 0, 0, 0.34);
}

.device-card__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.device-card__title {
  margin: 0;
  font-size: 21px;
  font-weight: 700;
}

.device-card__badges {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 10px;
}

.device-card__body {
  display: grid;
  gap: 10px;
}

.device-card__footer {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 10px;
}

.device-card__hint {
  margin: -4px 0 0;
  color: var(--muted);
  font-size: 12px;
}

.kv-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 12px;
  border: 1px solid rgba(148, 163, 184, 0.08);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.02);
}

.kv-row__label {
  color: var(--muted);
  font-size: 13px;
}

.kv-row__value {
  text-align: right;
  font-size: 14px;
  font-weight: 600;
  word-break: break-all;
}

.badge,
.mode-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  padding: 6px 10px;
  border: 1px solid transparent;
}

.badge--kind {
  background: rgba(148, 163, 184, 0.12);
  color: #cbd5e1;
}

.badge--online {
  background: rgba(34, 197, 94, 0.14);
  color: #86efac;
}

.badge--offline {
  background: rgba(239, 68, 68, 0.14);
  color: #fca5a5;
}

.badge--unknown {
  background: rgba(148, 163, 184, 0.12);
  color: #cbd5e1;
}

.mode-pill {
  background: rgba(148, 163, 184, 0.12);
  color: #dbe4f0;
  text-transform: uppercase;
  white-space: nowrap;
}

.mode-pill--alert {
  background: rgba(245, 158, 11, 0.14);
  color: #fde68a;
}

.select {
  width: 100%;
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: rgba(2, 6, 23, 0.72);
  color: var(--text);
  outline: none;
}

.btn {
  border: 0;
  border-radius: 12px;
  padding: 10px 16px;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  min-width: 136px;
}

.btn:disabled {
  opacity: 0.85;
  cursor: not-allowed;
}

.btn__spinner {
  width: 14px;
  height: 14px;
  border-radius: 999px;
  border: 2px solid rgba(255, 255, 255, 0.28);
  border-top-color: rgba(255, 255, 255, 0.95);
  animation: spin 0.8s linear infinite;
}

.btn--primary {
  color: white;
  background: linear-gradient(180deg, rgba(37, 99, 235, 0.96), rgba(29, 78, 216, 0.96));
}

.btn--secondary {
  color: #dbeafe;
  background: rgba(30, 41, 59, 0.78);
  border: 1px solid rgba(96, 165, 250, 0.2);
}

.error-box {
  margin-bottom: 18px;
  padding: 14px 16px;
  border-radius: 14px;
  background: rgba(127, 29, 29, 0.22);
  border: 1px solid rgba(239, 68, 68, 0.22);
  color: #fecaca;
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.chart-card {
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 18px;
  background: linear-gradient(180deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.86));
  box-shadow: var(--shadow);
}

.chart-card__header {
  margin-bottom: 12px;
}

.chart-card__header h3 {
  margin: 0;
  font-size: 18px;
}

.chart-card__header p {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 13px;
}

.chart-wrap {
  height: 320px;
}

.events-section {
  margin-bottom: 8px;
}

.section-head {
  margin-bottom: 14px;
}

.events-list {
  display: grid;
  gap: 12px;
}

.event-card {
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 16px;
  background: linear-gradient(180deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.86));
}

.event-card--critical {
  border-color: rgba(239, 68, 68, 0.34);
  background: linear-gradient(180deg, rgba(69, 10, 10, 0.55), rgba(15, 23, 42, 0.86));
}

.event-card--warning {
  border-color: rgba(245, 158, 11, 0.28);
  background: linear-gradient(180deg, rgba(69, 26, 3, 0.45), rgba(15, 23, 42, 0.86));
}

.event-card__top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.event-card__title {
  margin: 0;
  font-size: 17px;
}

.event-card__meta {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 13px;
}

.event-card__body {
  display: grid;
  gap: 10px;
}

.empty-box {
  padding: 16px;
  border-radius: 14px;
  border: 1px dashed rgba(148, 163, 184, 0.18);
  color: var(--muted);
  background: rgba(255, 255, 255, 0.02);
}

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(2, 6, 23, 0.78);
  backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  z-index: 1000;
}

.modal-card {
  width: min(1240px, 100%);
  max-height: 92vh;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 24px;
  padding: 20px;
  background: linear-gradient(180deg, rgba(17, 24, 39, 0.98), rgba(15, 23, 42, 0.96));
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
}

.modal-card__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.modal-card__actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 1100px) {
  .charts-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 860px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }

  .toolbar,
  .modal-card__header {
    flex-direction: column;
    align-items: flex-start;
  }
}

@media (max-width: 560px) {
  .app-shell {
    padding: 24px 14px 40px;
  }

  .device-card__footer {
    grid-template-columns: 1fr;
  }

  .btn {
    width: 100%;
  }

  .modal-backdrop {
    padding: 12px;
  }

  .modal-card {
    padding: 14px;
  }
}
</style>