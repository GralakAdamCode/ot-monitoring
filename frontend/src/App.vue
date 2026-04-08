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
import type { ChartOptions } from "chart.js";
import { Line } from "vue-chartjs";
import type {
  Device,
  TrafficPoint,
  DeviceLiveResponse
} from "./types/dashboard";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

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
  labels: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => formatTs(p.ts)),
  datasets: [
    {
      label: "Suma packet_rate",
      data: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => p.packet_rate_sum),
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
  labels: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => formatTs(p.ts)),
  datasets: [
    {
      label: "Byte count",
      data: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => p.byte_count_sum),
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
  labels: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => formatTs(p.ts)),
  datasets: [
    {
      label: "Średni jitter [ms]",
      data: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => p.avg_jitter_ms),
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
  labels: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => formatTs(p.ts)),
  datasets: [
    {
      label: "ML anomalies",
      data: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => p.ml_anomaly_count),
      borderColor: "rgba(239, 68, 68, 0.9)",
      backgroundColor: "rgba(239, 68, 68, 0.18)",
      fill: false,
      tension: 0.3,
      pointRadius: 2,
      pointHoverRadius: 4
    },
    {
      label: "Eventy",
      data: (liveDeviceData.value?.points ?? []).map((p: TrafficPoint) => p.event_count),
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

function statusBadgeClass(status: string) {
  if (status === "online") {
    return "bg-emerald-500/15 text-emerald-300";
  }
  if (status === "offline") {
    return "bg-red-500/15 text-red-300";
  }
  return "bg-slate-400/15 text-slate-300";
}

function severityCardClass(severity: string) {
  if (severity === "critical") {
    return "border-red-500/30 bg-gradient-to-b from-red-950/60 to-slate-900/90";
  }
  if (severity === "warning") {
    return "border-amber-500/30 bg-gradient-to-b from-amber-950/40 to-slate-900/90";
  }
  return "border-slate-700/70 bg-gradient-to-b from-slate-900/95 to-slate-900/85";
}

function severityPillClass(severity: string) {
  if (severity === "critical") {
    return "bg-red-500/15 text-red-300";
  }
  if (severity === "warning") {
    return "bg-amber-500/15 text-amber-200";
  }
  return "bg-slate-400/15 text-slate-200";
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
  <div
    class="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(59,130,246,0.18),transparent_30%),radial-gradient(circle_at_top_right,rgba(99,102,241,0.14),transparent_24%),linear-gradient(180deg,#070b14_0%,#0b1120_100%)] text-slate-200"
  >
    <div class="mx-auto max-w-7xl px-5 py-10 sm:px-6 lg:px-8">
      <header class="mb-7 grid gap-6">
        <div>
          <p class="mb-2 text-xs font-extrabold uppercase tracking-[0.16em] text-blue-400">
            OT MONITORING
          </p>
          <h1 class="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Panel sterowania środowiskiem
          </h1>
          <p class="mt-3 max-w-3xl text-sm text-slate-400 sm:text-base">
            Kliknij kafelek urządzenia, aby zobaczyć live view dla wybranego elementu.
          </p>
        </div>

        <div class="grid gap-3 md:grid-cols-3">
          <article class="rounded-2xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
            <span class="block text-sm text-slate-400">Urządzenia</span>
            <strong class="mt-2 block text-3xl font-extrabold tracking-tight text-white">
              {{ totalDevices }}
            </strong>
          </article>

          <article class="rounded-2xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
            <span class="block text-sm text-slate-400">Online</span>
            <strong class="mt-2 block text-3xl font-extrabold tracking-tight text-white">
              {{ onlineDevices }}
            </strong>
          </article>

          <article class="rounded-2xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
            <span class="block text-sm text-slate-400">Aktywne anomalie</span>
            <strong class="mt-2 block text-3xl font-extrabold tracking-tight text-white">
              {{ activeAnomalies }}
            </strong>
          </article>
        </div>
      </header>

      <section class="mb-5 flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <h2 class="text-xl font-semibold text-white">Urządzenia</h2>
          <p class="mt-1 text-sm text-slate-400">
            Zmieniaj tryby i obserwuj stan symulowanych elementów.
          </p>
        </div>

        <button
          class="inline-flex min-w-[148px] items-center justify-center gap-2 rounded-xl border border-blue-400/20 bg-slate-800/80 px-4 py-2.5 font-semibold text-blue-100 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-80"
          @click="loadData"
          :disabled="loading"
        >
          <span>Odśwież urządzenia</span>
          <span
            v-if="loading"
            class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
          ></span>
        </button>
      </section>

      <div
        v-if="error"
        class="mb-5 rounded-2xl border border-red-500/20 bg-red-950/30 px-4 py-3 text-sm text-red-200"
      >
        {{ error }}
      </div>

      <main class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="device in devices"
          :key="device.name"
          class="flex cursor-pointer flex-col gap-4 rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30 transition duration-200 hover:-translate-y-0.5 hover:border-blue-400/30"
          @click="openDeviceLive(device.name)"
        >
          <div class="flex items-start justify-between gap-3">
            <div>
              <h3 class="text-3xl font-bold tracking-tight text-white">
                {{ device.name }}
              </h3>

              <div class="mt-3 flex flex-wrap gap-2">
                <span class="inline-flex items-center justify-center rounded-full bg-slate-400/15 px-3 py-1 text-xs font-bold text-slate-200">
                  {{ device.kind }}
                </span>
                <span
                  class="inline-flex items-center justify-center rounded-full px-3 py-1 text-xs font-bold"
                  :class="statusBadgeClass(device.status)"
                >
                  {{ device.status }}
                </span>
              </div>
            </div>

            <span
              class="inline-flex whitespace-nowrap rounded-full bg-slate-400/15 px-3 py-1 text-xs font-bold uppercase text-slate-100"
              :class="device.anomaly_active ? 'bg-amber-500/15 text-amber-200' : ''"
            >
              {{ device.anomaly_mode }}
            </span>
          </div>

          <div class="grid gap-2.5">
            <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
              <span class="text-sm text-slate-400">IP</span>
              <span class="text-right text-sm font-semibold text-slate-100 break-all">
                {{ device.ip_address }}
              </span>
            </div>

            <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
              <span class="text-sm text-slate-400">Bind</span>
              <span class="text-right text-sm font-semibold text-slate-100 break-all">
                {{ device.bind_ip ?? "-" }}:{{ device.bind_port ?? "-" }}
              </span>
            </div>

            <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
              <span class="text-sm text-slate-400">Target</span>
              <span class="text-right text-sm font-semibold text-slate-100 break-all">
                {{ device.target_ip ?? "-" }}:{{ device.target_port ?? "-" }}
              </span>
            </div>
          </div>

          <div class="grid grid-cols-1 gap-2.5 sm:grid-cols-[1fr_auto]" @click.stop>
            <select
              class="w-full rounded-xl border border-slate-700/60 bg-slate-950/80 px-3 py-2.5 text-slate-100 outline-none"
              v-model="selectedModes[device.name]"
            >
              <option v-for="mode in modes" :key="mode" :value="mode">
                {{ mode }}
              </option>
            </select>

            <button
              class="inline-flex min-w-[110px] items-center justify-center gap-2 rounded-xl bg-gradient-to-b from-blue-600 to-blue-700 px-4 py-2.5 font-semibold text-white transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-80"
              @click.stop="saveMode(device.name)"
              :disabled="savingDevice === device.name"
            >
              <span>Zapisz</span>
              <span
                v-if="savingDevice === device.name"
                class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
              ></span>
            </button>
          </div>

          <p class="text-xs text-slate-400">
            Kliknij kartę, aby otworzyć Show live
          </p>
        </article>
      </main>

      <div
        v-if="liveModalOpen"
        class="fixed inset-0 z-[1000] flex items-center justify-center bg-slate-950/80 p-3 backdrop-blur md:p-6"
        @click="closeDeviceLive"
      >
        <div
          class="max-h-[92vh] w-full max-w-7xl overflow-auto rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/90 p-4 shadow-2xl shadow-black/50 md:p-6"
          @click.stop
        >
          <div class="mb-5 flex flex-col items-start justify-between gap-4 md:flex-row">
            <div>
              <p class="mb-2 text-xs font-extrabold uppercase tracking-[0.16em] text-blue-400">
                SHOW LIVE
              </p>
              <h2 class="text-2xl font-bold text-white">
                {{ liveDeviceData?.device.name ?? liveDeviceName }}
              </h2>
              <p class="mt-1 text-sm text-slate-400" v-if="liveDeviceData">
                {{ liveDeviceData.device.kind }} · {{ liveDeviceData.device.ip_address }} ·
                ostatnie {{ liveDeviceData.window_minutes }} minut
              </p>
            </div>

            <div class="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
              <button
                class="inline-flex min-w-[132px] items-center justify-center gap-2 rounded-xl border border-blue-400/20 bg-slate-800/80 px-4 py-2.5 font-semibold text-blue-100 transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-80"
                @click="loadDeviceLive"
                :disabled="liveLoading"
              >
                <span>Odśwież live</span>
                <span
                  v-if="liveLoading"
                  class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
                ></span>
              </button>

              <button
                class="inline-flex min-w-[132px] items-center justify-center rounded-xl border border-blue-400/20 bg-slate-800/80 px-4 py-2.5 font-semibold text-blue-100 transition hover:bg-slate-800"
                @click="closeDeviceLive"
              >
                Zamknij
              </button>
            </div>
          </div>

          <div v-if="liveDeviceData" class="mb-6 grid gap-4 xl:grid-cols-2">
            <article class="rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
              <div class="mb-3">
                <h3 class="text-xl font-semibold text-white">Ruch pakietów</h3>
                <p class="mt-1 text-sm text-slate-400">
                  Suma packet_rate z ostatnich 5 minut
                </p>
              </div>
              <div class="h-80">
                <Line :data="livePacketRateChartData" :options="chartOptions" />
              </div>
            </article>

            <article class="rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
              <div class="mb-3">
                <h3 class="text-xl font-semibold text-white">Byte count</h3>
                <p class="mt-1 text-sm text-slate-400">Wolumen ruchu w czasie</p>
              </div>
              <div class="h-80">
                <Line :data="liveByteCountChartData" :options="chartOptions" />
              </div>
            </article>

            <article class="rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
              <div class="mb-3">
                <h3 class="text-xl font-semibold text-white">Jitter</h3>
                <p class="mt-1 text-sm text-slate-400">
                  Średni jitter w oknach czasowych
                </p>
              </div>
              <div class="h-80">
                <Line :data="liveJitterChartData" :options="chartOptions" />
              </div>
            </article>

            <article class="rounded-3xl border border-slate-700/60 bg-gradient-to-b from-slate-900/95 to-slate-900/85 p-5 shadow-2xl shadow-black/30">
              <div class="mb-3">
                <h3 class="text-xl font-semibold text-white">Anomalie i eventy</h3>
                <p class="mt-1 text-sm text-slate-400">
                  ML + rule-based zdarzenia
                </p>
              </div>
              <div class="h-80">
                <Line :data="liveAnomalyChartData" :options="chartOptions" />
              </div>
            </article>
          </div>

          <section v-if="liveDeviceData">
            <div class="mb-4">
              <h2 class="text-xl font-semibold text-white">Ostatnie eventy</h2>
              <p class="mt-1 text-sm text-slate-400">
                Feed najnowszych anomalii i zdarzeń dla wybranego urządzenia.
              </p>
            </div>

            <div class="grid gap-3">
              <article
                v-for="event in liveDeviceData.events"
                :key="event.id"
                class="rounded-3xl border p-4"
                :class="severityCardClass(event.severity)"
              >
                <div class="mb-3 flex items-start justify-between gap-3">
                  <div>
                    <h3 class="text-lg font-semibold text-white">
                      {{ event.title }}
                    </h3>
                    <p class="mt-1 text-sm text-slate-400">
                      {{ formatTs(event.detected_at) }} · {{ event.event_type }} · {{ event.severity }}
                    </p>
                  </div>

                  <span
                    class="inline-flex rounded-full px-3 py-1 text-xs font-bold uppercase"
                    :class="severityPillClass(event.severity)"
                  >
                    {{ event.severity }}
                  </span>
                </div>

                <div class="grid gap-2.5">
                  <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
                    <span class="text-sm text-slate-400">Źródło</span>
                    <span class="text-right text-sm font-semibold text-slate-100 break-all">
                      {{ event.src_ip ?? "-" }}
                    </span>
                  </div>

                  <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
                    <span class="text-sm text-slate-400">Cel</span>
                    <span class="text-right text-sm font-semibold text-slate-100 break-all">
                      {{ event.dst_ip ?? "-" }}:{{ event.dst_port ?? "-" }}
                    </span>
                  </div>

                  <div class="flex items-center justify-between gap-3 rounded-xl border border-slate-700/40 bg-white/5 px-3 py-3">
                    <span class="text-sm text-slate-400">Protokół</span>
                    <span class="text-right text-sm font-semibold text-slate-100 break-all">
                      {{ event.protocol ?? "-" }}
                    </span>
                  </div>
                </div>
              </article>

              <div
                v-if="liveDeviceData.events.length === 0"
                class="rounded-2xl border border-dashed border-slate-700/60 bg-white/5 px-4 py-4 text-sm text-slate-400"
              >
                Brak eventów do wyświetlenia.
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  </div>
</template>