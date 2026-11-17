// Minimal WebUSB DFU/DfuSe implementation for firmware updates.
//
// The device is expected to expose the standard DFU interface class
// (0xFE/0x01) and, for STM32-style bootloaders, a DfuSe memory descriptor on
// the selected alternate setting. Raw binary images are supported.

const DFU_DNLOAD = 0x01;
const DFU_UPLOAD = 0x02;
const DFU_GETSTATUS = 0x03;
const DFU_CLRSTATUS = 0x04;
const DFU_GETSTATE = 0x05;
const DFU_ABORT = 0x06;

const DFU_STATUS_OK = 0x00;
const DFU_ERROR = 0x0a;

const DFU_IDLE = 0x02;
const DFU_DNBUSY = 0x04;
const DFU_DNLOAD_IDLE = 0x05;
const DFU_MANIFEST = 0x07;

const DFUSE_SET_ADDRESS = 0x21;
const DFUSE_ERASE_SECTOR = 0x41;

const DEFAULT_TRANSFER_SIZE = 1024;

export type DfuPhase = "erase" | "write" | "manifest" | "read";

export interface DfuProgress {
  phase: DfuPhase;
  done: number;
  total: number;
}

export interface DfuMemorySegment {
  start: number;
  end: number;
  sectorSize: number;
  readable: boolean;
  erasable: boolean;
  writable: boolean;
}

export interface DfuMemory {
  name: string;
  segments: DfuMemorySegment[];
}

export interface DfuDeviceInfo {
  vendorId: number;
  productId: number;
  productName: string;
  manufacturerName: string;
  serialNumber: string;
  interfaceNumber: number;
  alternateSetting: number;
  protocol: number;
  memoryName: string | null;
}

export interface DfuFlashOptions {
  startAddress?: number;
  transferSize?: number;
  onProgress?: (progress: DfuProgress) => void;
  onLog?: (message: string) => void;
}

export interface DfuUploadOptions {
  startAddress?: number;
  transferSize?: number;
  maxSize?: number;
  onProgress?: (progress: DfuProgress) => void;
  onLog?: (message: string) => void;
}

interface UsbAlternateInterface {
  alternateSetting: number;
  interfaceClass: number;
  interfaceSubclass: number;
  interfaceProtocol: number;
  interfaceName?: string | null;
}

interface UsbInterfaceDescriptor {
  interfaceNumber: number;
  alternates: UsbAlternateInterface[];
  claimed: boolean;
}

interface UsbConfiguration {
  configurationValue: number;
  interfaces: UsbInterfaceDescriptor[];
}

interface UsbControlTransferParameters {
  requestType: "class" | "standard" | "vendor";
  recipient: "device" | "interface" | "endpoint" | "other";
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

interface UsbDeviceHandle {
  vendorId: number;
  productId: number;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  opened: boolean;
  configurations: UsbConfiguration[];
  configuration: UsbConfiguration | null;
  open(): Promise<void>;
  close(): Promise<void>;
  selectConfiguration(configurationValue: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  releaseInterface(interfaceNumber: number): Promise<void>;
  selectAlternateInterface(
    interfaceNumber: number,
    alternateSetting: number,
  ): Promise<void>;
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
    filters: Array<{
      classCode?: number;
      subclassCode?: number;
      protocolCode?: number;
    }>;
  }): Promise<UsbDeviceHandle>;
}

interface DfuInterfaceSelection {
  configuration: UsbConfiguration;
  configurationIndex: number;
  intf: UsbInterfaceDescriptor;
  alternate: UsbAlternateInterface;
}

interface DfuStatus {
  status: number;
  pollTimeout: number;
  state: number;
}

export class DfuError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DfuError";
  }
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function findDfuInterfaces(device: UsbDeviceHandle): DfuInterfaceSelection[] {
  const selections: DfuInterfaceSelection[] = [];
  for (const [configurationIndex, configuration] of device.configurations.entries()) {
    for (const intf of configuration.interfaces) {
      for (const alternate of intf.alternates) {
        if (
          alternate.interfaceClass === 0xfe &&
          alternate.interfaceSubclass === 0x01 &&
          (alternate.interfaceProtocol === 0x01 ||
            alternate.interfaceProtocol === 0x02)
        ) {
          selections.push({
            configuration,
            configurationIndex,
            intf,
            alternate,
          });
        }
      }
    }
  }
  return selections;
}

function segmentAt(
  memory: DfuMemory,
  address: number,
): DfuMemorySegment | null {
  for (const segment of memory.segments) {
    if (address >= segment.start && address < segment.end) {
      return segment;
    }
  }
  return null;
}

function parseMemoryDescriptor(descriptor: string): DfuMemory | null {
  const firstSlash = descriptor.indexOf("/");
  if (!descriptor.startsWith("@") || firstSlash === -1) {
    return null;
  }

  const name = descriptor.slice(1, firstSlash).trim();
  const rest = descriptor.slice(firstSlash);
  const segments: DfuMemorySegment[] = [];
  const regionPattern =
    /\/\s*(0x[0-9a-fA-F]{1,8})\s*\/((?:\s*\d+\s*\*\s*\d+\s*[ BKM]\s*[a-g]\s*,?\s*)+)/g;
  const sectorPattern = /(\d+)\s*\*\s*(\d+)\s*([ BKM])\s*([a-g])/g;

  for (const region of rest.matchAll(regionPattern)) {
    const base = region[1];
    const specs = region[2];
    if (!base || !specs) continue;
    let address = Number.parseInt(base, 16);
    if (!Number.isFinite(address)) continue;
    for (const sector of specs.matchAll(sectorPattern)) {
      const countText = sector[1];
      const sizeText = sector[2];
      const unit = sector[3];
      const property = sector[4];
      if (!countText || !sizeText || !unit || !property) continue;
      const count = Number.parseInt(countText, 10);
      const size = Number.parseInt(sizeText, 10);
      const multiplier = unit === "M" ? 1024 * 1024 : unit === "K" ? 1024 : 1;
      const sectorSize = size * multiplier;
      if (count <= 0 || sectorSize <= 0) continue;
      const properties = property.charCodeAt(0) - 0x61 + 1;
      segments.push({
        start: address,
        end: address + count * sectorSize,
        sectorSize,
        readable: (properties & 0x01) !== 0,
        erasable: (properties & 0x02) !== 0,
        writable: (properties & 0x04) !== 0,
      });
      address += count * sectorSize;
    }
  }

  if (segments.length === 0) return null;
  return { name, segments };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class DfuSession {
  private readonly device: UsbDeviceHandle;
  private readonly configurationValue: number;
  private readonly intfNumber: number;
  private readonly alternateSetting: number;
  private memory: DfuMemory | null;
  private closed = false;

  readonly info: DfuDeviceInfo;

  private constructor(
    device: UsbDeviceHandle,
    selection: DfuInterfaceSelection,
    memory: DfuMemory | null,
  ) {
    this.device = device;
    this.configurationValue = selection.configuration.configurationValue;
    this.intfNumber = selection.intf.interfaceNumber;
    this.alternateSetting = selection.alternate.alternateSetting;
    this.memory = memory;
    this.info = {
      vendorId: device.vendorId,
      productId: device.productId,
      productName: device.productName ?? "",
      manufacturerName: device.manufacturerName ?? "",
      serialNumber: device.serialNumber ?? "",
      interfaceNumber: this.intfNumber,
      alternateSetting: this.alternateSetting,
      protocol: selection.alternate.interfaceProtocol,
      memoryName: memory?.name ?? null,
    };
  }

  static async request(): Promise<DfuSession> {
    const usb = getUsbApi();
    if (!usb) {
      throw new DfuError(
        "WebUSB is not available. Use a Chromium-based browser over HTTPS.",
      );
    }

    let device: UsbDeviceHandle;
    try {
      device = await usb.requestDevice({
        filters: [{ classCode: 0xfe, subclassCode: 0x01 }],
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "NotFoundError") {
        throw new DfuError("No device was selected.");
      }
      throw new DfuError(errorMessage(error));
    }

    try {
      await device.open();
    } catch (error) {
      throw new DfuError(errorMessage(error));
    }

    const selections = findDfuInterfaces(device);
    const dfu = selections.find(
      (selection) => selection.alternate.interfaceProtocol === 0x02,
    );
    if (!dfu) {
      try {
        await device.close();
      } catch {
        // The device was opened but no usable interface was found.
      }
      throw new DfuError(
        "No DFU interface found. Put the device into DFU mode and try again.",
      );
    }

    const session = new DfuSession(device, dfu, null);
    try {
      await session.open();
      const name = await session.resolveInterfaceName(dfu);
      const memory = parseMemoryDescriptor(name ?? "");
      if (memory) {
        session.memory = memory;
        session.info.memoryName = memory.name;
      }
    } catch (error) {
      await session.close();
      throw new DfuError(errorMessage(error));
    }
    return session;
  }

  get isDfuSe(): boolean {
    return this.memory !== null;
  }

  get memoryMap(): DfuMemory | null {
    return this.memory;
  }

  get defaultStartAddress(): number {
    const writable = this.memory?.segments.find((segment) => segment.writable);
    return writable?.start ?? 0x08000000;
  }

  private async resolveInterfaceName(
    selection: DfuInterfaceSelection,
  ): Promise<string | null> {
    if (selection.alternate.interfaceName) {
      return selection.alternate.interfaceName;
    }

    let descriptor: DataView;
    try {
      descriptor = await this.readConfigurationDescriptor(
        selection.configurationIndex,
      );
    } catch {
      return null;
    }

    const bytes = new Uint8Array(
      descriptor.buffer,
      descriptor.byteOffset,
      descriptor.byteLength,
    );
    let offset = 0;
    let stringIndex = 0;
    while (offset + 2 <= bytes.length) {
      const length = bytes[offset] ?? 0;
      const type = bytes[offset + 1] ?? 0;
      if (length < 2) break;
      if (
        type === 4 &&
        offset + 9 <= bytes.length &&
        bytes[offset + 2] === selection.intf.interfaceNumber &&
        bytes[offset + 3] === selection.alternate.alternateSetting
      ) {
        stringIndex = bytes[offset + 8] ?? 0;
        break;
      }
      offset += length;
    }

    if (!stringIndex) return null;
    try {
      return await this.readStringDescriptor(stringIndex);
    } catch {
      return null;
    }
  }

  private async readConfigurationDescriptor(index: number): Promise<DataView> {
    const header = await this.standardIn((2 << 8) | index, 0, 9);
    if (header.byteLength < 9) {
      throw new DfuError("The configuration descriptor is truncated.");
    }
    const total = header.getUint16(2, true);
    if (total < 9) {
      throw new DfuError("The configuration descriptor length is invalid.");
    }
    return this.standardIn((2 << 8) | index, 0, total);
  }

  private async readStringDescriptor(index: number): Promise<string> {
    for (const langId of [0x0409, 0]) {
      try {
        const data = await this.standardIn((3 << 8) | index, langId, 255);
        const length = data.getUint8(0);
        let text = "";
        for (let offset = 2; offset + 1 < length; offset += 2) {
          text += String.fromCharCode(data.getUint16(offset, true));
        }
        if (text) return text;
      } catch {
        // Try the next language ID.
      }
    }
    throw new DfuError(`Unable to read string descriptor ${index}.`);
  }

  private async standardIn(
    value: number,
    index: number,
    length: number,
  ): Promise<DataView> {
    const result = await this.device.controlTransferIn(
      {
        requestType: "standard",
        recipient: "device",
        request: 0x06,
        value,
        index,
      },
      length,
    );
    if (result.status !== "ok" || !result.data) {
      throw new DfuError(`Descriptor request failed: ${result.status}.`);
    }
    return result.data;
  }

  private async open(): Promise<void> {
    if (!this.device.opened) {
      await this.device.open();
    }
    if (
      this.device.configuration === null ||
      this.device.configuration.configurationValue !== this.configurationValue
    ) {
      await this.device.selectConfiguration(this.configurationValue);
    }

    const intf = this.selectedInterface();
    if (!intf.claimed) {
      try {
        await this.device.claimInterface(this.intfNumber);
      } catch (error) {
        if (!errorMessage(error).includes("already claimed")) throw error;
      }
    }

    try {
      if (intf.alternates.length > 1) {
        await this.device.selectAlternateInterface(
          this.intfNumber,
          this.alternateSetting,
        );
      }
    } catch (error) {
      // Chromium reports "Unable to set device interface" when the requested
      // alternate setting is already active.
      if (!errorMessage(error).includes("Unable to set")) throw error;
    }
  }

  private selectedInterface(): UsbInterfaceDescriptor {
    const configuration = this.device.configuration;
    const intf = configuration?.interfaces.find(
      (candidate) => candidate.interfaceNumber === this.intfNumber,
    );
    if (!intf) {
      throw new DfuError("The selected DFU interface is no longer available.");
    }
    return intf;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.device.releaseInterface(this.intfNumber);
    } catch {
      // The interface may already be released after a reset.
    }
    try {
      await this.device.close();
    } catch {
      // Ignore a device that already disconnected.
    }
  }

  async flash(data: Uint8Array, options: DfuFlashOptions = {}): Promise<void> {
    if (this.closed) {
      throw new DfuError("The DFU device is closed.");
    }
    if (data.byteLength === 0) {
      throw new DfuError("The firmware image is empty.");
    }

    const transferSize = options.transferSize ?? DEFAULT_TRANSFER_SIZE;
    if (!Number.isInteger(transferSize) || transferSize < 64 || transferSize > 4096) {
      throw new DfuError("Transfer size must be between 64 and 4096 bytes.");
    }

    try {
      const status = await this.getStatus();
      if (status.state === DFU_ERROR) {
        await this.clearStatus();
      }
    } catch (error) {
      options.onLog?.(`Unable to read DFU status: ${errorMessage(error)}`);
    }

    if (this.memory) {
      await this.flashDfuSe(data, transferSize, options);
    } else {
      await this.flashStandard(data, transferSize, options);
    }
  }

  private async flashDfuSe(
    data: Uint8Array,
    transferSize: number,
    options: DfuFlashOptions,
  ): Promise<void> {
    const memory = this.memory;
    if (!memory) throw new DfuError("No DfuSe memory map is available.");

    const startAddress = options.startAddress ?? this.defaultStartAddress;
    const segment = segmentAt(memory, startAddress);
    if (!segment || !segment.writable) {
      throw new DfuError(
        `Start address 0x${startAddress.toString(16)} is outside the writable flash region.`,
      );
    }
    if (startAddress + data.byteLength > segment.end) {
      throw new DfuError(
        `The image ends at 0x${(startAddress + data.byteLength).toString(16)}, past the flash region end 0x${segment.end.toString(16)}.`,
      );
    }

    options.onLog?.("Erasing DFU device memory.");
    await this.erase(startAddress, data.byteLength, options.onProgress);

    options.onLog?.("Copying firmware to DFU device.");
    let address = startAddress;
    let offset = 0;
    while (offset < data.byteLength) {
      const chunk = data.subarray(
        offset,
        Math.min(offset + transferSize, data.byteLength),
      );
      await this.dfuseCommand(DFUSE_SET_ADDRESS, address, 4);
      const written = await this.download(chunk, 2);
      if (written !== chunk.byteLength) {
        throw new DfuError(
          `Short DFU write: expected ${chunk.byteLength} bytes, wrote ${written}.`,
        );
      }
      const status = await this.pollUntil(
        (state) => state === DFU_DNLOAD_IDLE,
      );
      if (status.status !== DFU_STATUS_OK || status.state === DFU_ERROR) {
        throw new DfuError(
          `DFU download failed: state=${status.state}, status=${status.status}.`,
        );
      }
      address += written;
      offset += written;
      options.onProgress?.({
        phase: "write",
        done: offset,
        total: data.byteLength,
      });
    }

    options.onLog?.("Manifesting new firmware.");
    try {
      await this.dfuseCommand(DFUSE_SET_ADDRESS, startAddress, 4);
      await this.download(new Uint8Array(0), 0);
      await this.pollUntil((state) => state === DFU_MANIFEST);
    } catch (error) {
      // The bootloader commonly resets as soon as manifestation starts, so a
      // lost control transfer here is not a reliable failure signal.
      options.onLog?.(
        `Device reset during manifest; the image was written. (${errorMessage(error)})`,
      );
    }
  }

  private async flashStandard(
    data: Uint8Array,
    transferSize: number,
    options: DfuFlashOptions,
  ): Promise<void> {
    options.onLog?.("Copying firmware to DFU device.");
    let offset = 0;
    let transaction = 0;
    while (offset < data.byteLength) {
      const chunk = data.subarray(
        offset,
        Math.min(offset + transferSize, data.byteLength),
      );
      const written = await this.download(chunk, transaction++);
      if (written !== chunk.byteLength) {
        throw new DfuError(
          `Short DFU write: expected ${chunk.byteLength} bytes, wrote ${written}.`,
        );
      }
      const status = await this.pollUntil(
        (state) => state === DFU_DNLOAD_IDLE,
      );
      if (status.status !== DFU_STATUS_OK || status.state === DFU_ERROR) {
        throw new DfuError(
          `DFU download failed: state=${status.state}, status=${status.status}.`,
        );
      }
      offset += written;
      options.onProgress?.({
        phase: "write",
        done: offset,
        total: data.byteLength,
      });
    }

    options.onLog?.("Manifesting new firmware.");
    try {
      await this.download(new Uint8Array(0), 0);
      await this.pollUntil((state) => state === DFU_MANIFEST);
    } catch (error) {
      options.onLog?.(
        `Device reset during manifest; the image was written. (${errorMessage(error)})`,
      );
    }
  }

  async upload(options: DfuUploadOptions = {}): Promise<Uint8Array> {
    if (this.closed) {
      throw new DfuError("The DFU device is closed.");
    }

    const transferSize = options.transferSize ?? DEFAULT_TRANSFER_SIZE;
    if (!Number.isInteger(transferSize) || transferSize < 64 || transferSize > 4096) {
      throw new DfuError("Transfer size must be between 64 and 4096 bytes.");
    }

    const startAddress = options.startAddress ?? this.defaultStartAddress;
    let maxSize = options.maxSize ?? 0x40000;
    if (!Number.isInteger(maxSize) || maxSize <= 0) {
      throw new DfuError("Read size must be a positive number of bytes.");
    }

    let block = 0;
    if (this.memory) {
      const memory = this.memory;
      const segment = segmentAt(memory, startAddress);
      if (!segment) {
        throw new DfuError(
          `Start address 0x${startAddress.toString(16)} is outside the flash region.`,
        );
      }
      maxSize = Math.min(maxSize, segment.end - startAddress);
      const state = await this.getState();
      if (state !== DFU_IDLE) {
        await this.abortToIdle();
      }
      await this.dfuseCommand(DFUSE_SET_ADDRESS, startAddress, 4);
      await this.abortToIdle();
      block = 2;
    }

    const chunks: Uint8Array[] = [];
    let read = 0;
    while (read < maxSize) {
      const wanted = Math.min(transferSize, maxSize - read);
      const chunk = await this.uploadBlock(wanted, block++);
      if (chunk.byteLength === 0) break;
      chunks.push(chunk);
      read += chunk.byteLength;
      options.onProgress?.({ phase: "read", done: read, total: maxSize });
      if (chunk.byteLength < wanted) break;
    }

    if (read >= maxSize) {
      await this.abortToIdle();
    }

    const result = new Uint8Array(read);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    options.onLog?.(`Read ${read} bytes from the device.`);
    return result;
  }

  private async getState(): Promise<number> {
    const result = await this.device.controlTransferIn(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_GETSTATE,
        value: 0,
        index: this.intfNumber,
      },
      1,
    );
    if (result.status !== "ok" || !result.data) {
      throw new DfuError(`DFU state request failed: ${result.status}.`);
    }
    return result.data.getUint8(0);
  }

  private async abort(): Promise<void> {
    const result = await this.device.controlTransferOut(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_ABORT,
        value: 0,
        index: this.intfNumber,
      },
      undefined,
    );
    if (result.status !== "ok") {
      throw new DfuError(`DFU abort request failed: ${result.status}.`);
    }
  }

  private async abortToIdle(): Promise<void> {
    await this.abort();
    let state = await this.getState();
    if (state === DFU_ERROR) {
      await this.clearStatus();
      state = await this.getState();
    }
    if (state !== DFU_IDLE) {
      throw new DfuError(
        `Failed to return to DFU idle state after abort: state=${state}.`,
      );
    }
  }

  private async uploadBlock(length: number, block: number): Promise<Uint8Array> {
    const result = await this.device.controlTransferIn(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_UPLOAD,
        value: block,
        index: this.intfNumber,
      },
      length,
    );
    if (result.status !== "ok" || !result.data) {
      throw new DfuError(`DFU upload transfer failed: ${result.status}.`);
    }
    return new Uint8Array(
      result.data.buffer.slice(
        result.data.byteOffset,
        result.data.byteOffset + result.data.byteLength,
      ),
    );
  }

  private async erase(
    start: number,
    length: number,
    onProgress?: (progress: DfuProgress) => void,
  ): Promise<void> {
    const memory = this.memory;
    if (!memory) throw new DfuError("No DfuSe memory map is available.");

    const end = start + length;
    let address = start;
    const total = end - start;
    while (address < end) {
      const segment = segmentAt(memory, address);
      if (!segment) {
        throw new DfuError(
          `Address 0x${address.toString(16)} is outside the flash region.`,
        );
      }
      if (!segment.erasable) {
        throw new DfuError(
          `Address 0x${address.toString(16)} is in a non-erasable flash region.`,
        );
      }
      const sectorStart =
        segment.start +
        Math.floor((address - segment.start) / segment.sectorSize) *
          segment.sectorSize;
      await this.dfuseCommand(DFUSE_ERASE_SECTOR, sectorStart, 4);
      address = Math.min(sectorStart + segment.sectorSize, end);
      onProgress?.({
        phase: "erase",
        done: Math.min(address - start, total),
        total,
      });
    }
  }

  private async dfuseCommand(
    command: number,
    parameter: number,
    length: 1 | 4,
  ): Promise<void> {
    const payload = new Uint8Array(length + 1);
    payload[0] = command;
    if (length === 1) {
      payload[1] = parameter;
    } else {
      new DataView(payload.buffer).setUint32(1, parameter, true);
    }
    await this.download(payload, 0);
    const status = await this.pollUntil((state) => state !== DFU_DNBUSY);
    if (status.status !== DFU_STATUS_OK || status.state === DFU_ERROR) {
      throw new DfuError(
        `DfuSe command 0x${command.toString(16)} failed: state=${status.state}, status=${status.status}.`,
      );
    }
  }

  private async clearStatus(): Promise<void> {
    const result = await this.device.controlTransferOut(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_CLRSTATUS,
        value: 0,
        index: this.intfNumber,
      },
      undefined,
    );
    if (result.status !== "ok") {
      throw new DfuError(`DFU clear-status request failed: ${result.status}.`);
    }
  }

  private async download(data: ArrayBufferView, block: number): Promise<number> {
    const result = await this.device.controlTransferOut(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_DNLOAD,
        value: block,
        index: this.intfNumber,
      },
      data as BufferSource,
    );
    if (result.status !== "ok") {
      throw new DfuError(`DFU download transfer failed: ${result.status}.`);
    }
    return result.bytesWritten;
  }

  private async getStatus(): Promise<DfuStatus> {
    const result = await this.device.controlTransferIn(
      {
        requestType: "class",
        recipient: "interface",
        request: DFU_GETSTATUS,
        value: 0,
        index: this.intfNumber,
      },
      6,
    );
    if (result.status !== "ok" || !result.data) {
      throw new DfuError(`DFU status request failed: ${result.status}.`);
    }
    const data = result.data;
    return {
      status: data.getUint8(0),
      pollTimeout: data.getUint32(1, true) & 0xffffff,
      state: data.getUint8(4),
    };
  }

  private async pollUntil(
    predicate: (state: number) => boolean,
  ): Promise<DfuStatus> {
    let status = await this.getStatus();
    while (!predicate(status.state) && status.state !== DFU_ERROR) {
      if (status.pollTimeout > 0) {
        await sleep(status.pollTimeout);
      }
      status = await this.getStatus();
    }
    return status;
  }
}
