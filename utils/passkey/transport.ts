import {
  bytesToHex,
  hexToBytes,
  PasskeyError,
  statusWord,
  type SendApdu,
} from "./apdu";

interface UsbControlTransferParameters {
  requestType: "vendor";
  recipient: "interface";
  request: number;
  value: number;
  index: number;
}

interface UsbInTransferResult {
  status: string;
  data?: DataView;
}

interface UsbOutTransferResult {
  status: string;
  bytesWritten: number;
}

export interface UsbDeviceLike {
  open(): Promise<void>;
  close(): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  controlTransferIn(
    setup: UsbControlTransferParameters,
    length: number,
  ): Promise<UsbInTransferResult>;
  controlTransferOut(
    setup: UsbControlTransferParameters,
    data?: BufferSource,
  ): Promise<UsbOutTransferResult>;
}

interface UsbApi {
  requestDevice(options: {
    filters: Array<{ classCode?: number }>;
  }): Promise<UsbDeviceLike>;
  addEventListener(
    type: "disconnect",
    listener: (event: { device: UsbDeviceLike }) => void,
  ): void;
  removeEventListener(
    type: "disconnect",
    listener: (event: { device: UsbDeviceLike }) => void,
  ): void;
}

function getUsbApi(): UsbApi | undefined {
  if (typeof navigator === "undefined" || !("usb" in navigator)) {
    return undefined;
  }
  return (navigator as Navigator & { usb?: UsbApi }).usb;
}

export function isWebUsbAvailable(): boolean {
  return getUsbApi() !== undefined;
}

const INTERFACE_NUMBER = 1;
const RESPONSE_LENGTH = 1500;
const STATUS_TIMEOUT_MS = 25000;
const MAX_CHAIN_LENGTH = 32;

function delay(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<undefined>();
  setTimeout(() => resolve(undefined), ms);
  return promise;
}

function dataToHex(data: DataView | undefined): string {
  if (!data) return "";
  return bytesToHex(
    new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
  );
}

export class PasskeyTransport {
  private device: UsbDeviceLike | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private disconnectHandler:
    | ((event: { device: UsbDeviceLike }) => void)
    | null = null;

  constructor(private readonly onDisconnect?: () => void) {}

  async connect(): Promise<void> {
    const usb = getUsbApi();
    if (!usb) {
      throw new PasskeyError(
        "WebUSB is not available. Use a Chromium-based browser over HTTPS.",
        "NO_WEBUSB",
      );
    }
    if (this.device) {
      await this.disconnect();
    }
    let device: UsbDeviceLike | undefined;
    try {
      device = await usb.requestDevice({
        filters: [{ classCode: 0xff }],
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : "";
      if (name === "NotFoundError") {
        throw new PasskeyError("No device was selected.", "NO_DEVICE");
      }
      throw new PasskeyError(
        error instanceof Error ? error.message : "Unable to open the device.",
        "OPEN_FAILED",
      );
    }
    try {
      await device.open();
      await device.claimInterface(INTERFACE_NUMBER);
    } catch {
      try {
        await device.close();
      } catch {
        // Ignore a close failure after a failed open.
      }
      throw new PasskeyError(
        "Unable to claim the device. Close other browser tabs, GPG agents, or smart-card services and reconnect.",
        "CLAIM_FAILED",
      );
    }
    this.device = device;
    this.disconnectHandler = (event) => {
      if (event.device === device) {
        this.device = null;
        this.onDisconnect?.();
      }
    };
    usb.addEventListener("disconnect", this.disconnectHandler);
  }

  async disconnect(): Promise<void> {
    const device = this.device;
    const usb = getUsbApi();
    if (usb && this.disconnectHandler) {
      usb.removeEventListener("disconnect", this.disconnectHandler);
    }
    this.disconnectHandler = null;
    this.device = null;
    if (device) {
      try {
        await device.close();
      } catch {
        // The device may already be gone.
      }
    }
  }

  transaction<T>(operation: (send: SendApdu) => Promise<T>): Promise<T> {
    const run = this.queue.then(
      () => operation(this.send),
      () => operation(this.send),
    );
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private send: SendApdu = async (capdu, chain) => {
    let rapdu = await this.exchange(capdu);
    for (let i = 0; i < MAX_CHAIN_LENGTH; i++) {
      const sw = statusWord(rapdu);
      if (!sw.startsWith("61")) {
        return rapdu;
      }
      const sw2 = sw.slice(2);
      const next = chain ? chain(sw2) : `00C00000${sw2}`;
      rapdu = `${rapdu.slice(0, -4)}${await this.exchange(next)}`;
    }
    throw new PasskeyError("The device returned too many response blocks.", "CHAIN_LIMIT");
  };

  private async exchange(capdu: string): Promise<string> {
    const device = this.device;
    if (!device) {
      throw new PasskeyError("No device is connected.", "NOT_CONNECTED");
    }
    const out = await device.controlTransferOut(
      {
        requestType: "vendor",
        recipient: "interface",
        request: 0,
        value: 0,
        index: INTERFACE_NUMBER,
      },
      hexToBytes(capdu) as BufferSource,
    );
    if (out.status !== "ok") {
      throw new PasskeyError("The device rejected the command transfer.", "TRANSFER_FAILED");
    }

    const deadline = Date.now() + STATUS_TIMEOUT_MS;
    let ready = false;
    while (Date.now() < deadline) {
      const status = await device.controlTransferIn(
        {
          requestType: "vendor",
          recipient: "interface",
          request: 2,
          value: 0,
          index: INTERFACE_NUMBER,
        },
        1,
      );
      if (status.status === "stall") {
        throw new PasskeyError(
          "The device is busy. Reconnect it and try again.",
          "DEVICE_BUSY",
        );
      }
      const state = status.data
        ? new Uint8Array(status.data.buffer, status.data.byteOffset, status.data.byteLength)[0]
        : undefined;
      if (state === 0) {
        ready = true;
        break;
      }
      if (state === 1) {
        await delay(50);
        continue;
      }
      throw new PasskeyError(
        state === undefined
          ? "The device did not report a valid state."
          : `The device reported state ${state}.`,
        "DEVICE_STATE",
      );
    }
    if (!ready) {
      throw new PasskeyError("The device did not finish the command in time.", "TIMEOUT");
    }

    const response = await device.controlTransferIn(
      {
        requestType: "vendor",
        recipient: "interface",
        request: 1,
        value: 0,
        index: INTERFACE_NUMBER,
      },
      RESPONSE_LENGTH,
    );
    if (response.status !== "ok") {
      throw new PasskeyError("The device did not return a response.", "NO_RESPONSE");
    }
    return dataToHex(response.data);
  }
}
