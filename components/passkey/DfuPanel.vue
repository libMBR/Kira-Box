<template>
  <section class="pk-panel">
    <div class="pk-panel-head">
      <h2>Firmware update (DFU)</h2>
      <span class="pk-badge">Session only</span>
    </div>
    <p class="pk-muted pk-panel-description">
      This tab is available only after DFU actions are enabled under Device
      settings. It disappears after a full page reload.
    </p>

    <div class="dfu-warning">
      <strong>Firmware flashing can permanently damage the device.</strong>
      Only flash an image built for this exact hardware. Do not switch tabs,
      close the page, or unplug the device while the update is running. The
      browser may ask for permission to access the USB device again.
    </div>

    <p class="pk-muted">
      <strong>Short the debug contacts to enter DFU mode.</strong> The DFU panel
      below becomes available after the device disconnects from the settings
      session.
    </p>
    <p v-if="!connected" class="pk-muted">
      Click Connect, then select the DFU device in the browser prompt. The
      device must already be in DFU mode.
    </p>
    <div v-else class="pk-placeholder pk-placeholder-tall">
      Waiting for the device to disconnect. Short the debug contacts, or use
      Enter DFU mode below.
    </div>

    <div v-if="connected" class="pk-block">
      <h3>Enter DFU mode</h3>
      <p class="pk-muted">
        Sends the vendor command to restart the device into its bootloader. The
        device will disconnect from the settings session. The PIN is kept in
        memory only.
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
        <button
          class="pk-btn pk-btn-danger"
          :disabled="busy"
          @click="enterDfuMode"
        >
          Enter DFU mode
        </button>
      </div>
      <p v-if="adminPinError" class="pk-field-error">{{ adminPinError }}</p>
      <p v-if="message" class="pk-muted">{{ message }}</p>
    </div>

    <div v-else class="pk-block dfu-native">
      <h3>DFU device</h3>
      <div class="dfu-actions">
        <button
          v-if="!session"
          class="pk-btn"
          :disabled="connecting || flashing || reading"
          @click="connect"
        >
          {{ connecting ? "Connecting…" : "Connect DFU device" }}
        </button>
        <button
          v-else
          class="pk-btn pk-btn-secondary"
          :disabled="flashing || reading"
          @click="disconnect"
        >
          Disconnect
        </button>
        <span class="pk-muted">{{ statusText }}</span>
      </div>

      <p v-if="error" class="pk-field-error">{{ error }}</p>

      <template v-if="session">
        <table class="pk-table pk-table-info">
          <tbody>
            <tr>
              <th>Device</th>
              <td>{{ deviceName }}</td>
            </tr>
            <tr>
              <th>USB ID</th>
              <td class="pk-code">{{ usbId }}</td>
            </tr>
            <tr v-if="memorySummary">
              <th>Memory</th>
              <td class="pk-code">{{ memorySummary }}</td>
            </tr>
          </tbody>
        </table>

        <p class="pk-muted">
          Select a raw <code>.bin</code> image. The image is written starting at
          the address below and must fit entirely inside one writable flash
          region.
        </p>

        <div class="dfu-grid">
          <label class="dfu-field">
            <span>Firmware image</span>
            <input
              class="pk-input"
              type="file"
              accept=".bin,application/octet-stream"
              :disabled="flashing || reading"
              @change="onFile"
            >
          </label>
          <label v-if="isDfuSe" class="dfu-field">
            <span>Start address</span>
            <input
              v-model="startAddress"
              class="pk-input pk-code"
              type="text"
              spellcheck="false"
              :disabled="flashing || reading"
            >
          </label>
          <label class="dfu-field">
            <span>Transfer size (bytes)</span>
            <input
              v-model.number="transferSize"
              class="pk-input"
              type="number"
              min="64"
              max="4096"
              step="64"
              :disabled="flashing || reading"
            >
          </label>
        </div>

        <p v-if="firmware" class="pk-muted">
          Selected: <span class="pk-code">{{ firmware.name }}</span>
          ({{ firmware.data.byteLength }} bytes)
        </p>

        <div class="dfu-read">
          <h4>Read firmware</h4>
          <p class="pk-muted">
            Reads the current flash contents from the start address and saves
            them as a raw binary file.
          </p>
          <div class="dfu-actions">
            <label class="dfu-field">
              <span>Read size (bytes)</span>
              <input
                v-model.number="maxReadSize"
                class="pk-input"
                type="number"
                min="64"
                step="1024"
                :disabled="flashing || reading"
              >
            </label>
            <button
              class="pk-btn pk-btn-secondary"
              :disabled="flashing || reading"
              @click="readFirmware"
            >
              {{ reading ? "Reading…" : "Read firmware" }}
            </button>
          </div>
        </div>

        <div class="dfu-actions">
          <button
            class="pk-btn pk-btn-danger"
            :disabled="!firmware || flashing || reading"
            @click="flash"
          >
            {{ flashing ? "Flashing…" : "Flash firmware" }}
          </button>
          <span v-if="progress" class="pk-muted">
            {{ phaseLabel }} {{ progressPercent }}%
          </span>
        </div>

        <progress
          v-if="progress"
          class="dfu-progress"
          :value="progress.done"
          :max="progress.total || 1"
        />

        <div v-if="log.length" class="dfu-log" aria-live="polite">
          <p v-for="(line, index) in log" :key="index">{{ line }}</p>
        </div>
      </template>
    </div>
  </section>
</template>

<script lang="ts" setup>
import { computed, onBeforeUnmount, ref, shallowRef, watch } from "vue";
import type { Notify, Runner } from "~/composables/usePasskeyDevice";
import { PasskeyError } from "~/utils/passkey/apdu";
import { selectAdmin, verifyAdminPin } from "~/utils/passkey/device";
import {
  DfuSession,
  type DfuProgress,
  isWebUsbAvailable,
} from "~/utils/passkey/dfu";

const props = defineProps<{
  run: Runner;
  busy: boolean;
  notify: Notify;
  connected: boolean;
}>();

const session = shallowRef<DfuSession | null>(null);
const connecting = ref(false);
const flashing = ref(false);
const reading = ref(false);
const firmware = ref<{ name: string; data: Uint8Array } | null>(null);
const startAddress = ref("");
const transferSize = ref(1024);
const maxReadSize = ref(0x40000);
const progress = ref<DfuProgress | null>(null);
const log = ref<string[]>([]);
const error = ref("");

const adminPin = ref("");
const adminPinError = ref("");
const message = ref("");

const isDfuSe = computed(() => session.value?.isDfuSe === true);
const deviceName = computed(() => {
  const info = session.value?.info;
  if (!info) return "";
  return info.productName || "Unknown DFU device";
});
const usbId = computed(() => {
  const info = session.value?.info;
  if (!info) return "";
  return `0x${info.vendorId.toString(16).padStart(4, "0")}:0x${info.productId
    .toString(16)
    .padStart(4, "0")}`;
});
const memorySummary = computed(() => {
  const memory = session.value?.memoryMap;
  if (!memory) return "";
  return `${memory.name}: ${memory.segments
    .map(
      (segment) =>
        `0x${segment.start.toString(16)}-0x${(segment.end - 1).toString(16)}`,
    )
    .join(", ")}`;
});
const statusText = computed(() => {
  if (!session.value) return "No DFU device connected.";
  return isDfuSe.value ? "DfuSe bootloader connected." : "DFU device connected.";
});
const progressPercent = computed(() => {
  if (!progress.value || progress.value.total === 0) return 0;
  return Math.round((progress.value.done / progress.value.total) * 100);
});
const phaseLabel = computed(() => {
  switch (progress.value?.phase) {
    case "erase":
      return "Erasing";
    case "write":
      return "Writing";
    case "manifest":
      return "Finishing";
    case "read":
      return "Reading";
    default:
      return "";
  }
});

function pushLog(line: string): void {
  log.value = [...log.value, line].slice(-200);
}

function errorText(errorValue: unknown): string {
  if (errorValue instanceof Error) return errorValue.message;
  return String(errorValue);
}

async function connect(): Promise<void> {
  error.value = "";
  progress.value = null;
  if (!isWebUsbAvailable()) {
    error.value =
      "WebUSB is not available. Use a Chromium-based browser over HTTPS.";
    return;
  }
  connecting.value = true;
  try {
    const opened = await DfuSession.request();
    session.value = opened;
    startAddress.value = `0x${opened.defaultStartAddress
      .toString(16)
      .padStart(8, "0")}`;
    log.value = [];
    pushLog(
      opened.isDfuSe
        ? "DfuSe device connected."
        : "DFU device connected (no DfuSe memory map).",
    );
  } catch (errorValue) {
    error.value = errorText(errorValue);
  } finally {
    connecting.value = false;
  }
}

async function disconnect(): Promise<void> {
  const current = session.value;
  session.value = null;
  firmware.value = null;
  progress.value = null;
  if (current) {
    await current.close();
  }
}

async function onFile(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  firmware.value = null;
  error.value = "";
  if (!file) return;
  if (!/\.bin$/i.test(file.name)) {
    error.value = "Select a raw .bin firmware image.";
    input.value = "";
    return;
  }
  try {
    const buffer = await file.arrayBuffer();
    if (buffer.byteLength === 0) {
      error.value = "The selected firmware image is empty.";
      return;
    }
    firmware.value = { name: file.name, data: new Uint8Array(buffer) };
  } catch (errorValue) {
    error.value = errorText(errorValue);
  }
}

async function readFirmware(): Promise<void> {
  if (!session.value) return;
  error.value = "";
  progress.value = null;

  let parsedStart: number | undefined;
  if (session.value.isDfuSe) {
    parsedStart = Number.parseInt(startAddress.value, 16);
    if (!Number.isFinite(parsedStart) || parsedStart < 0) {
      error.value = "Enter a valid hexadecimal start address.";
      return;
    }
  }
  const maxSize = Number(maxReadSize.value);
  if (!Number.isInteger(maxSize) || maxSize <= 0) {
    error.value = "Read size must be a positive number of bytes.";
    return;
  }

  reading.value = true;
  try {
    const data = await session.value.upload({
      startAddress: parsedStart,
      transferSize: Number(transferSize.value),
      maxSize,
      onProgress: (value) => {
        progress.value = value;
      },
      onLog: pushLog,
    });
    const blob = new Blob([data], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = parsedStart
      ? `firmware-0x${parsedStart.toString(16)}.bin`
      : "firmware.bin";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    pushLog(`Read ${data.byteLength} bytes.`);
    props.notify("success", "Firmware read completed.");
  } catch (errorValue) {
    const text = errorText(errorValue);
    error.value = text;
    pushLog(text);
    props.notify("error", text);
  } finally {
    reading.value = false;
  }
}

async function flash(): Promise<void> {
  if (!session.value || !firmware.value) return;
  error.value = "";
  progress.value = null;
  log.value = [];

  let parsedStart: number | undefined;
  if (session.value.isDfuSe) {
    parsedStart = Number.parseInt(startAddress.value, 16);
    if (!Number.isFinite(parsedStart) || parsedStart < 0) {
      error.value = "Enter a valid hexadecimal start address.";
      return;
    }
  }
  const size = Number(transferSize.value);
  if (!Number.isInteger(size) || size < 64 || size > 4096) {
    error.value = "Transfer size must be between 64 and 4096 bytes.";
    return;
  }

  if (
    !window.confirm(
      `Flash ${firmware.value.name} to ${deviceName.value}? Do not disconnect the device until the update finishes.`,
    )
  ) {
    return;
  }

  flashing.value = true;
  try {
    await session.value.flash(firmware.value.data, {
      startAddress: parsedStart,
      transferSize: size,
      onProgress: (value) => {
        progress.value = value;
      },
      onLog: pushLog,
    });
    progress.value = { phase: "manifest", done: 1, total: 1 };
    pushLog("Firmware update completed.");
    props.notify("success", "Firmware update completed.");
  } catch (errorValue) {
    const text = errorText(errorValue);
    error.value = text;
    pushLog(text);
    props.notify("error", text);
  } finally {
    flashing.value = false;
  }
}

watch(
  () => props.connected,
  (isConnected) => {
    if (isConnected) {
      void disconnect();
    }
  },
);

onBeforeUnmount(() => {
  void session.value?.close();
});

async function enterDfuMode(): Promise<void> {
  adminPinError.value = "";
  message.value = "";
  if (adminPin.value.length === 0) {
    adminPinError.value = "Enter the Admin PIN first.";
    return;
  }
  if (
    !window.confirm(
      "Restart the device into DFU mode? It will disconnect from the settings session, and the browser will need permission to access it again.",
    )
  ) {
    return;
  }
  try {
    await props.run(
      async (send) => {
        await selectAdmin(send);
        await verifyAdminPin(send, adminPin.value);
        const response = await send("00FF2222");
        if (response.slice(-4) !== "9000") {
          throw new PasskeyError(
            `The device rejected the DFU command (${response.slice(-4).toUpperCase()}). It may not support DFU mode.`,
            "DFU_REJECTED",
          );
        }
        return true;
      },
      { silent: true, rethrow: true },
    );
    message.value =
      "The device accepted the command without disconnecting. If it restarted, use Connect in the panel above and select the DFU device; otherwise it may already be in DFU mode.";
  } catch (errorValue) {
    if (errorValue instanceof PasskeyError && /^63c/i.test(errorValue.code ?? "")) {
      adminPinError.value = errorValue.message;
      return;
    }
    if (errorValue instanceof PasskeyError && errorValue.code === "DFU_REJECTED") {
      message.value = errorValue.message;
      return;
    }
    message.value =
      "The device stopped responding through the settings interface. That is expected when it restarts into DFU mode. Use Connect in the panel above and select the DFU device.";
  }
}
</script>

<style scoped>
.dfu-warning {
  padding: 0.9rem 1rem;
  border: 1px solid #f0d58c;
  border-radius: 4px;
  background: #fff8e1;
  color: #6b5200;
  font-size: 0.92rem;
  line-height: 1.45;
  margin: 1rem 0;
}

.dfu-warning strong {
  display: block;
  margin-bottom: 0.3rem;
}

.dfu-actions {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  flex-wrap: wrap;
}

.dfu-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.8rem;
  margin: 1rem 0;
}

.dfu-read {
  margin: 1rem 0;
  padding-top: 0.8rem;
  border-top: 1px solid #eee;
}

.dfu-read h4 {
  margin: 0 0 0.3rem;
  font-size: 0.95rem;
}

.dfu-field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  font-size: 0.9rem;
}

.dfu-field > span {
  color: #555;
}

.dfu-progress {
  width: 100%;
  height: 12px;
  margin: 0.8rem 0;
}

.dfu-log {
  max-height: 220px;
  overflow: auto;
  margin-top: 0.8rem;
  padding: 0.6rem 0.75rem;
  border-radius: 4px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: Consolas, monospace;
  font-size: 0.8rem;
  line-height: 1.45;
}

.dfu-log p {
  margin: 0.15rem 0;
}

@media (max-width: 600px) {
  .dfu-grid {
    grid-template-columns: 1fr;
  }
}
</style>
