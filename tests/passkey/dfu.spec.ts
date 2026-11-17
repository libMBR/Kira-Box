import { afterEach, describe, expect, it, vi } from "vitest";
import { DfuSession } from "../../utils/passkey/dfu";

interface Transfer {
  request: number;
  value: number;
  data: Uint8Array;
}

class FakeDfuDevice {
  opened = false;
  configuration: unknown = null;
  readonly configurations = [
    {
      configurationValue: 1,
      interfaces: [
        {
          interfaceNumber: 0,
          claimed: false,
          alternates: [
            {
              alternateSetting: 0,
              interfaceClass: 0xfe,
              interfaceSubclass: 0x01,
              interfaceProtocol: 0x02,
              interfaceName:
                "@Sample Flash /0x10000000/04*002Kg,01*008Kg",
            },
          ],
        },
      ],
    },
  ];

  state = 0x02;
  readonly transfers: Transfer[] = [];

  async open(): Promise<void> {
    this.opened = true;
  }

  async close(): Promise<void> {
    this.opened = false;
  }

  async selectConfiguration(value: number): Promise<void> {
    this.configuration = this.configurations.find(
      (config) => config.configurationValue === value,
    );
  }

  async claimInterface(): Promise<void> {}
  async releaseInterface(): Promise<void> {}
  async selectAlternateInterface(): Promise<void> {}

  async controlTransferOut(
    setup: { request: number; value: number },
    data?: ArrayBufferView,
  ): Promise<{ status: string; bytesWritten: number }> {
    const bytes = data
      ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
      : new Uint8Array();
    this.transfers.push({
      request: setup.request,
      value: setup.value,
      data: new Uint8Array(bytes),
    });
    if (setup.request === 0x01) {
      this.state =
        setup.value === 0 && bytes.byteLength === 0 ? 0x07 : 0x05;
    }
    return { status: "ok", bytesWritten: bytes.byteLength };
  }

  async controlTransferIn(
    setup: { request: number },
    length: number,
  ): Promise<{ status: string; data: DataView }> {
    const buffer = new ArrayBuffer(length);
    const view = new DataView(buffer);
    if (setup.request === 0x03) {
      view.setUint8(4, this.state);
    } else if (setup.request === 0x05) {
      view.setUint8(0, this.state);
    }
    return { status: "ok", data: view };
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DfuSession", () => {
  it("erases and writes a raw image through DfuSe commands", async () => {
    const device = new FakeDfuDevice();
    vi.stubGlobal("navigator", {
      usb: { requestDevice: async () => device },
    });

    const session = await DfuSession.request();
    expect(session.isDfuSe).toBe(true);
    expect(session.defaultStartAddress).toBe(0x10000000);

    const progress: Array<{ phase: string; done: number; total: number }> = [];
    await session.flash(new Uint8Array(2048), {
      transferSize: 1024,
      onProgress: (value) => progress.push(value),
    });

    const erase = device.transfers.find(
      (transfer) =>
        transfer.request === 0x01 &&
        transfer.value === 0 &&
        transfer.data[0] === 0x41,
    );
    expect(erase?.data.slice(1)).toEqual(
      new Uint8Array([0x00, 0x00, 0x00, 0x10]),
    );

    const write = device.transfers.find(
      (transfer) => transfer.request === 0x01 && transfer.value === 2,
    );
    expect(write?.data.byteLength).toBe(1024);
    expect(progress).toContainEqual({
      phase: "write",
      done: 2048,
      total: 2048,
    });
  });
});
