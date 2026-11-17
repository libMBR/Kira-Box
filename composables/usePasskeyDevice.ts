import { onBeforeUnmount, onMounted, ref } from "vue";
import { clearPasskeyCache } from "~/composables/usePasskeyCache";
import { PasskeyError, type SendApdu } from "~/utils/passkey/apdu";
import {
  readDeviceInfo,
  validateDeviceInfo,
  type DeviceInfo,
} from "~/utils/passkey/device";
import {
  isWebUsbAvailable,
  PasskeyTransport,
} from "~/utils/passkey/transport";

export interface Notice {
  kind: "success" | "error";
  text: string;
}

export type Notify = (kind: Notice["kind"], text: string) => void;

export type Runner = <T>(
  operation: (send: SendApdu) => Promise<T>,
  options?: { silent?: boolean; rethrow?: boolean },
) => Promise<T | null>;

function errorText(error: unknown): string {
  if (error instanceof PasskeyError || error instanceof Error) {
    return error.message;
  }
  return "Unexpected error.";
}

export function usePasskeyDevice() {
  const connected = ref(false);
  const connecting = ref(false);
  const busy = ref(false);
  const supported = ref(true);
  const device = ref<DeviceInfo | null>(null);
  const notice = ref<Notice | null>(null);
  const pendingDevice = ref<DeviceInfo | null>(null);
  const hardwareWarning = ref("");

  const transport = new PasskeyTransport(() => {
    clearPasskeyCache();
    connected.value = false;
    device.value = null;
    pendingDevice.value = null;
    hardwareWarning.value = "";
    notice.value = {
      kind: "error",
      text: "The device was disconnected.",
    };
  });

  function notify(kind: Notice["kind"], text: string): void {
    notice.value = { kind, text };
  }

  function clearNotice(): void {
    notice.value = null;
  }

  onMounted(() => {
    supported.value = isWebUsbAvailable();
  });

  onBeforeUnmount(() => {
    void transport.disconnect();
  });

  async function connect(): Promise<void> {
    if (!isWebUsbAvailable()) {
      notify(
        "error",
        "WebUSB is not available. Use a Chromium-based browser over HTTPS.",
      );
      return;
    }
    connecting.value = true;
    busy.value = true;
    clearNotice();
    pendingDevice.value = null;
    hardwareWarning.value = "";
    try {
      await transport.connect();
      clearPasskeyCache();
      let info: DeviceInfo;
      try {
        info = await transport.transaction((send) => readDeviceInfo(send));
      } catch (error) {
        const detail =
          error instanceof Error && error.message ? ` ${error.message}` : "";
        throw new PasskeyError(
          `Unable to identify the device.${detail} This tool only works with supported UsrKey devices.`,
          "UNSUPPORTED",
        );
      }
      const check = validateDeviceInfo(info);
      if (!check.ok) {
        clearPasskeyCache();
        pendingDevice.value = info;
        hardwareWarning.value = check.reason;
        device.value = null;
        connected.value = false;
        return;
      }
      device.value = info;
      pendingDevice.value = null;
      hardwareWarning.value = "";
      clearPasskeyCache();
      connected.value = true;
    } catch (error) {
      await transport.disconnect();
      connected.value = false;
      device.value = null;
      pendingDevice.value = null;
      hardwareWarning.value = "";
      notify("error", errorText(error));
    } finally {
      connecting.value = false;
      busy.value = false;
    }
  }

  function continueAnyway(): void {
    const pending = pendingDevice.value;
    if (!pending) return;
    device.value = pending;
    pendingDevice.value = null;
    hardwareWarning.value = "";
    connected.value = true;
    clearNotice();
  }

  async function disconnect(): Promise<void> {
    await transport.disconnect();
    clearPasskeyCache();
    connected.value = false;
    device.value = null;
    pendingDevice.value = null;
    hardwareWarning.value = "";
    clearNotice();
  }

  async function run<T>(
    operation: (send: SendApdu) => Promise<T>,
    options: { silent?: boolean; rethrow?: boolean } = {},
  ): Promise<T | null> {
    if (!connected.value) {
      if (!options.silent) notify("error", "Connect a device first.");
      return null;
    }
    busy.value = true;
    try {
      return await transport.transaction(operation);
    } catch (error) {
      if (!options.silent) notify("error", errorText(error));
      if (options.rethrow) throw error;
      return null;
    } finally {
      busy.value = false;
    }
  }

  return {
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
  };
}
