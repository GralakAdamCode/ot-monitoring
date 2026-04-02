<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

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

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const devices = ref<Device[]>([]);
const modes = ref<string[]>([]);
const loading = ref(false);
const savingDevice = ref<string | null>(null);
const error = ref<string | null>(null);
const selectedModes = ref<Record<string, string>>({});

const totalDevices = computed(() => devices.value.length);
const onlineDevices = computed(
  () => devices.value.filter((d) => d.status === "online").length
);
const activeAnomalies = computed(
  () => devices.value.filter((d) => d.anomaly_active).length
);

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

function statusClass(status: string) {
  if (status === "online") return "badge badge--online";
  if (status === "offline") return "badge badge--offline";
  return "badge badge--unknown";
}

onMounted(loadData);
</script>

<template>
  <div class="app-shell">
    <header class="hero">
      <div class="hero__content">
        <p class="hero__eyebrow">OT MONITORING</p>
        <h1 class="hero__title">Panel sterowania środowiskiem</h1>
        <p class="hero__subtitle">
          Prosty dashboard do podglądu urządzeń i zmiany trybów pracy.
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
        {{ loading ? "Ładowanie..." : "Odśwież" }}
      </button>
    </section>

    <div v-if="error" class="error-box">
      {{ error }}
    </div>

    <main class="device-grid">
      <article v-for="device in devices" :key="device.name" class="device-card">
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

        <div class="device-card__footer">
          <select class="select" v-model="selectedModes[device.name]">
            <option v-for="mode in modes" :key="mode" :value="mode">
              {{ mode }}
            </option>
          </select>

          <button
            class="btn btn--primary"
            @click="saveMode(device.name)"
            :disabled="savingDevice === device.name"
          >
            {{ savingDevice === device.name ? "Zapisywanie..." : "Zapisz" }}
          </button>
        </div>
      </article>
    </main>
  </div>
</template>