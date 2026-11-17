<template>
  <div class="app">
    <h1>Passkey Management</h1>
    <p class="description">
      Manage passkey hardware over WebUSB. Rewritten version in Vue + Nuxt + TypeScript,
      deprecating previous Flutter + Dart and React version.
    </p>
    <p class="pk-muted">
      This tool only works with supported hardware. Other devices and
      unsupported firmware versions may not work properly.
    </p>

    <div v-if="notice" class="pk-notice" :class="notice.kind">
      <span>{{ notice.text }}</span>
      <button class="pk-notice-close" aria-label="Dismiss" @click="clearNotice">
        ×
      </button>
    </div>
    <div v-if="!supported" class="pk-notice error">
      WebUSB is not available. Use a Chromium-based browser over HTTPS.
    </div>

    <section class="pk-panel">
      <div class="pk-panel-head">
        <h2>Device</h2>
        <button
          v-if="!connected"
          class="pk-btn"
          :disabled="busy || connecting || !supported"
          @click="connect"
        >
          {{ connecting ? "Connecting…" : "Connect device" }}
        </button>
        <button v-else class="pk-btn pk-btn-secondary" :disabled="busy" @click="disconnect">
          Disconnect
        </button>
      </div>
      <p class="pk-muted pk-panel-description">
        Close other browser tabs, GPG agents, or smart-card services and
        connect the device first.
      </p>

      <table v-if="connected && device" class="pk-table pk-table-info">
        <tbody>
          <tr><th>Firmware</th><td>{{ device.firmwareVersion }}</td></tr>
          <tr><th>Model</th><td>{{ device.model }}</td></tr>
          <tr><th>Serial number</th><td class="pk-code">{{ device.serialNumber }}</td></tr>
          <tr><th>Chip ID</th><td class="pk-code">{{ device.chipId }}</td></tr>
        </tbody>
      </table>
      <p v-else class="pk-muted">
        No device is connected currently.
      </p>
    </section>

    <template v-if="connected || dfuEnabled">
      <div class="pk-tabs" role="tablist" aria-label="Passkey Management sections">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          class="pk-tab"
          :class="{ active: activeTab === tab.key }"
          role="tab"
          :aria-selected="activeTab === tab.key"
          @click="activeTab = tab.key"
        >
          {{ tab.label }}
        </button>
      </div>

      <DfuPanel
        v-if="activeTab === 'dfu'"
        :run="run"
        :busy="busy"
        :notify="notify"
        :connected="connected"
      />
      <template v-else-if="connected">
        <DevicePanel
          v-if="activeTab === 'device'"
          :run="run"
          :busy="busy"
          :device="device"
          :notify="notify"
        />
        <OathPanel
          v-else-if="activeTab === 'oath'"
          :run="run"
          :busy="busy"
          :notify="notify"
        />
        <OpenPgpPanel
          v-else-if="activeTab === 'openpgp'"
          :run="run"
          :busy="busy"
          :notify="notify"
        />
        <PivPanel
          v-else
          :run="run"
          :busy="busy"
          :notify="notify"
        />
      </template>
      <section v-else class="pk-panel">
        <p class="pk-muted">
          Device disconnected. Reconnect the device to use this section,
          or switch to the DFU tab to work with the bootloader.
        </p>
      </section>
    </template>

    <div v-if="pendingDevice && hardwareWarning" class="pk-modal-backdrop">
      <div
        class="pk-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="hardware-warning-title"
      >
        <h2 id="hardware-warning-title">Unsupported hardware detected</h2>
        <p>
          The connected device does not match the supported hardware profile.
          It may be incompatible, damaged, or running a newer firmware. Continuing
          may fail or could damage the device.
        </p>
        <table class="pk-table pk-table-info">
          <tbody>
            <tr><th>Firmware</th><td>{{ pendingDevice.firmwareVersion }}</td></tr>
            <tr><th>Model</th><td>{{ pendingDevice.model }}</td></tr>
            <tr><th>Serial number</th><td class="pk-code">{{ pendingDevice.serialNumber }}</td></tr>
            <tr><th>Chip ID</th><td class="pk-code">{{ pendingDevice.chipId }}</td></tr>
          </tbody>
        </table>
        <p class="pk-field-error">{{ hardwareWarning }}</p>
        <div class="pk-modal-actions">
          <button class="pk-btn pk-btn-secondary" :disabled="busy" @click="disconnect">
            Disconnect
          </button>
          <button class="pk-btn pk-btn-danger" :disabled="busy" @click="continueAnyway">
            Continue Anyway
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed, ref, watch } from "vue";
import DevicePanel from "~/components/passkey/DevicePanel.vue";
import DfuPanel from "~/components/passkey/DfuPanel.vue";
import OathPanel from "~/components/passkey/OathPanel.vue";
import OpenPgpPanel from "~/components/passkey/OpenPgpPanel.vue";
import PivPanel from "~/components/passkey/PivPanel.vue";
import { usePasskeyDevice } from "~/composables/usePasskeyDevice";
import { usePasskeyFeatures } from "~/composables/usePasskeyFeatures";

useHead({
  title: "Passkey Management - Kira Box",
  meta: [
    {
      name: "description",
      content:
        "Manage passkey hardware locally over WebUSB: TOTP/HOTP, OpenPGP, PIV, device settings, and firmware DFU.",
    },
  ],
});

type TabKey = "device" | "oath" | "openpgp" | "piv" | "dfu";

const baseTabs: Array<{ key: TabKey; label: string }> = [
  { key: "device", label: "Device" },
  { key: "oath", label: "TOTP / HOTP" },
  { key: "openpgp", label: "OpenPGP" },
  { key: "piv", label: "PIV" },
];

const activeTab = ref<TabKey>("device");
const { dfuEnabled } = usePasskeyFeatures();
const tabs = computed(() =>
  dfuEnabled.value
    ? [...baseTabs, { key: "dfu" as TabKey, label: "DFU" }]
    : baseTabs,
);

watch(dfuEnabled, (enabled) => {
  if (!enabled && activeTab.value === "dfu") activeTab.value = "device";
});

const {
  connected,
  connecting,
  busy,
  supported,
  device,
  notice,
  pendingDevice,
  hardwareWarning,
  connect,
  continueAnyway,
  disconnect,
  run,
  notify,
  clearNotice,
} = usePasskeyDevice();
</script>

<style>
.app {
  padding: 2rem;
  text-align: left;
  max-width: 800px;
  margin: 0 auto;
}

.description {
  color: #666;
  margin-bottom: 1.5rem;
}

.pk-panel {
  border: 1px solid #ddd;
  border-radius: 6px;
  padding: 1.2rem;
  margin: 1.5rem 0;
  background: #fff;
}

.pk-panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

.pk-panel-head h2 {
  margin: 0;
}

.pk-panel-description {
  margin: 0.5rem 0 1rem;
}

.pk-panel-head > .pk-btn {
  flex: 0 0 auto;
  align-self: flex-start;
  white-space: nowrap;
}

.pk-panel h2,
.pk-panel h3 {
  margin-top: 0;
}

.pk-panel h3 {
  margin: 1.4rem 0 0.6rem;
  font-size: 1.05rem;
}

.pk-muted {
  color: #666;
  font-size: 0.92rem;
}

.pk-inline {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.6rem;
  margin: 0.6rem 0;
}

.pk-form {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.pk-form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  align-items: center;
}

.pk-input {
  padding: 0.7rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  min-width: 0;
  background: #fff;
  color: #000;
}

.pk-input-small {
  max-width: 140px;
}

.pk-btn {
  padding: 0.75rem 1.2rem;
  background: #007bff;
  color: #fff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background 0.2s;
}

.pk-btn:hover:not(:disabled) {
  background: #0056b3;
}

.pk-btn-secondary {
  background: #3070de;
}

.pk-btn-danger {
  background: #c0392b;
}

.pk-btn-danger:hover:not(:disabled) {
  background: #922b21;
}

.pk-btn:disabled,
.pk-link-btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.pk-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 0.7rem;
  margin: 1rem 0;
}

.pk-switch {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
  padding: 0.8rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  background: #f8f9fb;
  color: #333;
  cursor: pointer;
  font-size: 0.95rem;
  text-align: left;
}

.pk-switch strong {
  color: #3070de;
}

.pk-switch strong.pk-switch-unknown {
  color: #888;
}

.pk-block {
  margin-top: 1.4rem;
  padding-top: 1rem;
  border-top: 1px solid #eee;
}

.pk-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.6rem;
}

.pk-table {
  width: 100%;
  max-width: 100%;
  border-collapse: collapse;
  margin: 0.6rem 0 1rem;
  font-size: 0.95rem;
}

.pk-table th,
.pk-table td {
  text-align: left;
  padding: 0.5rem 0.4rem;
  border-bottom: 1px solid #eee;
  vertical-align: top;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.pk-table th {
  font-weight: 600;
  color: #444;
}

.pk-table-info {
  table-layout: fixed;
}

.pk-table-info th {
  width: 34%;
  overflow-wrap: normal;
  word-break: normal;
}

.pk-table-info td {
  width: 66%;
}

.pk-field-error {
  margin: 0.25rem 0 0;
  color: #c0392b;
  font-size: 0.85rem;
}

.pk-progress {
  width: 100%;
  height: 10px;
  overflow: hidden;
  border-radius: 5px;
  background: #eceff4;
  margin: 0.5rem 0;
}

.pk-progress-fill {
  height: 100%;
  width: 0;
  border-radius: 5px;
  background: #3070de;
  transition: width 0.3s ease;
}

.pk-input-full {
  width: 100%;
  box-sizing: border-box;
}

.pk-table-actions {
  white-space: nowrap;
}

.pk-code {
  font-family: Consolas, "Courier New", monospace;
  letter-spacing: 0.04em;
  overflow-wrap: anywhere;
  word-break: break-all;
}

.pk-countdown {
  margin-left: 0.5rem;
}

.pk-badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  background: #eef3ff;
  color: #3070de;
  font-size: 0.75rem;
}

.pk-link-btn {
  background: none;
  border: none;
  color: #007bff;
  cursor: pointer;
  padding: 0 0.4rem;
  font-size: 0.9rem;
}

.pk-link-btn:hover:not(:disabled) {
  text-decoration: underline;
}

.pk-link-danger {
  color: #c0392b;
}

.pk-check {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.92rem;
  color: #444;
}

.pk-inner {
  padding: 0.8rem;
  border: 1px solid #eee;
  border-radius: 4px;
  background: #fafbfc;
}

.pk-notice {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.8rem 1rem;
  border-radius: 4px;
  margin: 1rem 0;
}

.pk-notice.success {
  background: #eaf7ee;
  color: #1e6b34;
}

.pk-notice.error {
  background: #fdecea;
  color: #922b21;
}

.pk-notice-close {
  background: none;
  border: none;
  color: inherit;
  font-size: 1.2rem;
  cursor: pointer;
}

.pk-tabs {
  display: flex;
  flex-wrap: nowrap;
  justify-content: flex-start;
  gap: 1.25rem;
  margin-top: 1rem;
  overflow-x: auto;
  overflow-y: hidden;
  padding: 0 0 4px;
  -webkit-overflow-scrolling: touch;
  scrollbar-width: thin;
}

.pk-tab {
  flex: 0 0 auto;
  white-space: nowrap;
  padding: 0.55rem 0;
  border: 0;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  background: none;
  color: #555;
  cursor: pointer;
  font-size: 0.95rem;
}

.pk-tab:hover {
  color: #3070de;
}

.pk-tab.active {
  background: none;
  color: #3070de;
  border-bottom-color: #3070de;
}

.pk-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 160px;
  padding: 1rem;
  border: 1px dashed #ddd;
  border-radius: 4px;
  background: #fafbfc;
  color: #888;
  text-align: center;
  font-size: 0.92rem;
}

.pk-placeholder-tall {
  min-height: 320px;
}

.pk-danger-zone {
  border-top: 1px solid #eee;
}

.pk-danger-zone > summary {
  padding: 0.4rem 0;
  color: #c0392b;
  cursor: pointer;
  font-weight: 600;
}

.pk-danger-body {
  padding-top: 0.4rem;
}

.pk-notice {
  overflow-wrap: anywhere;
}

.pk-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  background: rgba(0, 0, 0, 0.45);
}

.pk-modal {
  width: 100%;
  max-width: 560px;
  max-height: 90vh;
  overflow-y: auto;
  padding: 1.25rem;
  border-radius: 6px;
  background: #fff;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
}

.pk-modal h2 {
  margin-top: 0;
}

.pk-modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.6rem;
  flex-wrap: wrap;
  margin-top: 1rem;
}

@media (max-width: 600px) {
  .app {
    padding: 1rem;
  }

  .pk-panel {
    padding: 1rem;
  }

  .pk-table-actions {
    white-space: normal;
  }
}
</style>
