<template>
  <section class="pk-panel">
    <h2>Device settings</h2>
    <p class="pk-muted">
      Enter the Admin PIN to read the current configuration.
    </p>

    <div class="pk-inline">
      <input
        v-model="adminPin"
        class="pk-input"
        type="password"
        autocomplete="new-password"
        placeholder="Admin PIN"
        @input="adminPinError = ''"
      >
      <button class="pk-btn" :disabled="busy" @click="loadConfig(true)">
        Unlock settings
      </button>
    </div>
    <p v-if="adminPinError" class="pk-field-error">{{ adminPinError }}</p>

    <p v-if="!config" class="pk-muted">
      Enter the Admin PIN to load the current values.
    </p>
    <div class="pk-block">
      <h3>Flash usage</h3>
      <div
        class="pk-progress"
        role="progressbar"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-valuenow="flashPercent ?? 0"
      >
        <div
          class="pk-progress-fill"
          :style="{ width: `${flashPercent ?? 0}%` }"
        />
      </div>
      <p class="pk-muted">
        <template v-if="flashUsage">
          {{ flashUsage.usedKiB }} KiB used of {{ flashUsage.totalKiB }} KiB
          <template v-if="flashPercent !== null">({{ flashPercent }}%)</template>.
        </template>
        <template v-else-if="flashUsageNotice">
          {{ flashUsageNotice }}
        </template>
        <template v-else>
          Enter the Admin PIN to read flash usage.
        </template>
      </p>
    </div>
    <div class="pk-grid">
      <button
        v-for="item in switches"
        :key="item.key"
        class="pk-switch"
        :disabled="busy || !config"
        @click="toggleSwitch(item.key, item.value)"
      >
        <span>{{ item.label }}</span>
        <strong :class="{ 'pk-switch-unknown': item.value === null }">
          {{ item.value === null ? "—" : item.value ? "On" : "Off" }}
        </strong>
      </button>
    </div>

    <div v-if="config?.layout === 'v1'" class="pk-block">
      <h3>Touch cache time</h3>
      <div class="pk-inline">
        <input
          v-model.number="cacheTime"
          class="pk-input pk-input-small"
          type="number"
          min="0"
          max="255"
          placeholder="0-255"
          @input="cacheError = ''"
        >
        <span class="pk-muted">seconds</span>
        <button class="pk-btn" :disabled="busy" @click="updateCacheTime">
          Save cache time
        </button>
      </div>
      <p v-if="cacheError" class="pk-field-error">{{ cacheError }}</p>
    </div>

    <div class="pk-block">
      <h3>Change Admin PIN</h3>
      <div class="pk-form">
        <input
          v-model="newAdminPin"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="New Admin PIN (6-64 characters)"
          @input="adminPinChangeError = ''"
        >
        <input
          v-model="confirmAdminPin"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Confirm new Admin PIN"
          @input="adminPinChangeError = ''"
        >
        <button class="pk-btn" :disabled="busy" @click="updateAdminPin">
          Change Admin PIN
        </button>
        <p v-if="adminPinChangeError" class="pk-field-error">
          {{ adminPinChangeError }}
        </p>
      </div>
    </div>

    <details class="pk-block pk-danger-zone">
      <summary>Dangerous actions</summary>
      <div class="pk-danger-body">
        <h3>Reset applications</h3>
        <p class="pk-muted">
          Resetting an application permanently erases its data. The Admin PIN is
          required.
        </p>
        <div class="pk-actions">
          <button
            v-for="item in resetTargets"
            :key="item.key"
            class="pk-btn pk-btn-danger"
            :disabled="busy"
            @click="reset(item.key)"
          >
            Reset {{ item.label }}
          </button>
        </div>

        <h3>Maintenance</h3>
        <div class="pk-actions">
          <button class="pk-btn pk-btn-danger" :disabled="busy" @click="repair">
            Repair NFC
          </button>
          <button class="pk-btn pk-btn-danger" :disabled="busy" @click="resetAll">
            Reset all data
          </button>
        </div>
        <p class="pk-muted">
          Reset all data is a factory reset. It only starts after the Admin PIN
          retries are used up, and the device must be touched while it flashes.
        </p>

        <h3>Firmware DFU</h3>
        <p class="pk-muted">
          Adds a DFU tab for this browser session only. Firmware flashing is
          irreversible if the wrong image is used.
        </p>
        <div class="pk-actions">
          <button
            v-if="!dfuEnabled"
            class="pk-btn pk-btn-danger"
            :disabled="busy"
            @click="enableDfuActions"
          >
            Enable DFU Actions
          </button>
          <button
            v-else
            class="pk-btn pk-btn-secondary"
            :disabled="busy"
            @click="disableDfuActions"
          >
            Disable DFU Actions
          </button>
        </div>
        <p v-if="dfuEnabled" class="pk-muted">
          DFU actions are enabled. Use the DFU tab above.
        </p>
      </div>
    </details>
  </section>
</template>

<script lang="ts" setup>
import { computed, ref, watch } from "vue";
import { usePasskeyCache } from "~/composables/usePasskeyCache";
import { usePasskeyFeatures } from "~/composables/usePasskeyFeatures";
import type { Notify, Runner } from "~/composables/usePasskeyDevice";
import {
  changeAdminPin,
  factoryReset,
  readDeviceConfigData,
  readFlashUsage,
  repairNfc,
  resetApplet,
  selectAdmin,
  setConfigSwitch,
  setTouchCacheTime,
  verifyAdminPin,
  type Applet,
  type ConfigSwitch,
  type DeviceConfig,
  type DeviceInfo,
  type FlashUsage,
} from "~/utils/passkey/device";

const props = defineProps<{
  run: Runner;
  busy: boolean;
  device: DeviceInfo | null;
  notify: Notify;
}>();

const { deviceConfig } = usePasskeyCache();
const { dfuEnabled, enableDfuActions, disableDfuActions } =
  usePasskeyFeatures();
const adminPin = ref("");
const newAdminPin = ref("");
const confirmAdminPin = ref("");
const adminPinError = ref("");
const adminPinChangeError = ref("");
const cacheError = ref("");
const config = ref<DeviceConfig | null>(deviceConfig.value);
const cacheTime = ref(deviceConfig.value?.touchCacheTime ?? 0);
const flashUsage = ref<FlashUsage | null>(null);
const flashUsageNotice = ref("");

const flashPercent = computed(() => {
  const usage = flashUsage.value;
  if (!usage || usage.totalKiB <= 0) return null;
  return Math.min(100, Math.round((usage.usedKiB / usage.totalKiB) * 100));
});

const resetTargets: Array<{ key: Applet; label: string }> = [
  { key: "openpgp", label: "OpenPGP" },
  { key: "piv", label: "PIV" },
  { key: "oath", label: "TOTP / HOTP" },
  { key: "ndef", label: "NDEF" },
];

const switches = computed<
  Array<{ key: ConfigSwitch; label: string; value: boolean | null }>
>(() => {
  const current = config.value;
  if (!current) {
    return [
      { key: "led", label: "LED", value: null },
      { key: "hotp", label: "HOTP on touch", value: null },
      { key: "ndefReadonly", label: "NDEF read-only", value: null },
      { key: "ndefEnabled", label: "NDEF enabled", value: null },
      { key: "webusbLanding", label: "WebUSB landing page", value: null },
      { key: "keyboardReturn", label: "Keyboard return", value: null },
    ];
  }
  const items: Array<{
    key: ConfigSwitch;
    label: string;
    value: boolean | null;
  }> = [
    { key: "led", label: "LED", value: current.ledOn },
    { key: "hotp", label: "HOTP on touch", value: current.hotpOn },
    { key: "ndefReadonly", label: "NDEF read-only", value: current.ndefReadonly },
  ];
  if (current.layout === "v1") {
    items.push(
      { key: "sigTouch", label: "Signature touch", value: current.sigTouch },
      { key: "decTouch", label: "Encryption touch", value: current.decTouch },
      { key: "autTouch", label: "Authentication touch", value: current.autTouch },
    );
  } else {
    items.push(
      { key: "ndefEnabled", label: "NDEF enabled", value: current.ndefEnabled },
      {
        key: "webusbLanding",
        label: "WebUSB landing page",
        value: current.webusbLandingEnabled,
      },
      {
        key: "keyboardReturn",
        label: "Keyboard return",
        value: current.keyboardReturnEnabled,
      },
    );
  }
  return items;
});

watch(
  () => props.device,
  () => {
    config.value = null;
    deviceConfig.value = null;
    adminPin.value = "";
    newAdminPin.value = "";
    confirmAdminPin.value = "";
    adminPinError.value = "";
    adminPinChangeError.value = "";
    cacheError.value = "";
    flashUsage.value = null;
    flashUsageNotice.value = "";
  },
);

async function loadConfig(showMessage: boolean): Promise<void> {
  const device = props.device;
  if (!device) return;
  adminPinError.value = "";
  if (adminPin.value.length === 0) {
    adminPinError.value = "Enter the Admin PIN first.";
    return;
  }
  try {
    const result = await props.run(
      async (send) => {
        await selectAdmin(send);
        await verifyAdminPin(send, adminPin.value);
        const nextConfig = await readDeviceConfigData(
          send,
          device.firmwareVersion,
        );
        let usage: FlashUsage | null = null;
        let usageNotice = "";
        try {
          usage = await readFlashUsage(send);
        } catch {
          usageNotice = "Flash usage is not reported by this firmware.";
        }
        return { config: nextConfig, usage, usageNotice };
      },
      { silent: true, rethrow: true },
    );
    if (result) {
      config.value = result.config;
      deviceConfig.value = result.config;
      cacheTime.value = result.config.touchCacheTime;
      flashUsage.value = result.usage;
      flashUsageNotice.value = result.usageNotice;
      if (showMessage) props.notify("success", "Settings loaded.");
    }
  } catch (error) {
    adminPinError.value =
      error instanceof Error ? error.message : "Unable to load settings.";
  }
}

async function toggleSwitch(
  key: ConfigSwitch,
  value: boolean | null,
): Promise<void> {
  if (value === null) return;
  const ok = await props.run(async (send) => {
    await setConfigSwitch(send, adminPin.value, key, !value);
    return true;
  });
  if (ok) {
    props.notify("success", "Setting updated.");
    await loadConfig(false);
  }
}

async function updateCacheTime(): Promise<void> {
  const seconds = cacheTime.value;
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 255) {
    cacheError.value = "Cache time must be between 0 and 255 seconds.";
    return;
  }
  cacheError.value = "";
  try {
    await props.run(
      async (send) => {
        await setTouchCacheTime(send, adminPin.value, seconds);
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Touch cache time updated.");
    await loadConfig(false);
  } catch (error) {
    cacheError.value =
      error instanceof Error ? error.message : "Unable to update cache time.";
  }
}

async function updateAdminPin(): Promise<void> {
  adminPinChangeError.value = "";
  if (newAdminPin.value !== confirmAdminPin.value) {
    adminPinChangeError.value = "The new Admin PIN entries do not match.";
    return;
  }
  try {
    await props.run(
      async (send) => {
        await changeAdminPin(send, adminPin.value, newAdminPin.value);
        return true;
      },
      { silent: true, rethrow: true },
    );
    adminPin.value = newAdminPin.value;
    newAdminPin.value = "";
    confirmAdminPin.value = "";
    props.notify("success", "Admin PIN changed.");
  } catch (error) {
    adminPinChangeError.value =
      error instanceof Error ? error.message : "Unable to change the Admin PIN.";
  }
}

async function reset(applet: Applet): Promise<void> {
  if (!window.confirm(`Reset ${applet.toUpperCase()} and erase its data?`)) return;
  const ok = await props.run(async (send) => {
    await resetApplet(send, adminPin.value, applet);
    return true;
  });
  if (ok) {
    props.notify("success", `${applet.toUpperCase()} was reset.`);
    await loadConfig(false);
  }
}

async function repair(): Promise<void> {
  if (
    !window.confirm(
      "Repair the NFC configuration? Only use this on affected hardware.",
    )
  ) {
    return;
  }
  const ok = await props.run(async (send) => {
    await repairNfc(send, adminPin.value);
    return true;
  });
  if (ok) props.notify("success", "NFC configuration repaired.");
}

async function resetAll(): Promise<void> {
  if (
    !window.confirm(
      "This erases all applications and settings. The device must be touched while it flashes. Continue?",
    )
  ) {
    return;
  }
  const ok = await props.run(async (send) => {
    await factoryReset(send);
    return true;
  });
  if (ok) {
    props.notify("success", "The device was reset.");
    config.value = null;
    deviceConfig.value = null;
  }
}
</script>
