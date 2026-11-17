import { describe, expect, it } from "vitest";
import {
  readDeviceConfigData,
  readFlashUsage,
  setConfigSwitch,
  validateDeviceInfo,
  isLegacyFirmware,
  type DeviceInfo,
} from "../../utils/passkey/device";

const info: DeviceInfo = {
  firmwareVersion: "a1b2c3d4-latest",
  model: "USRKEY Test Device",
  serialNumber: "TEST-SERIAL-0001",
  chipId: "00112233445566778899AABBCCDDEEFF",
};

describe("device protection", () => {
  it("accepts the connected hardware build", () => {
    expect(validateDeviceInfo(info)).toEqual({ ok: true });
  });

  it("accepts a numeric supported firmware", () => {
    expect(validateDeviceInfo({ ...info, firmwareVersion: "1.4.9" })).toEqual({
      ok: true,
    });
  });

  it("rejects other hardware and newer firmware", () => {
    expect(validateDeviceInfo({ ...info, model: "OtherKey" }).ok).toBe(false);
    expect(validateDeviceInfo({ ...info, firmwareVersion: "3.0.0" }).ok).toBe(false);
  });

  it("compares firmware numerically", () => {
    expect(isLegacyFirmware("1.10.0")).toBe(false);
    expect(isLegacyFirmware("1.4.9")).toBe(true);
    expect(isLegacyFirmware("0badc0de-latest")).toBe(false);
    expect(isLegacyFirmware("a1b2c3d4-latest")).toBe(false);
  });
});

describe("device configuration", () => {
  it("parses the newer layout", async () => {
    const send = async (capdu: string) =>
      capdu === "0042000000" ? "0101010101019000" : "9000";
    const config = await readDeviceConfigData(send, "2.1.0");
    expect(config).toMatchObject({
      layout: "v2",
      ledOn: true,
      hotpOn: true,
      ndefReadonly: true,
      ndefEnabled: true,
      webusbLandingEnabled: true,
      keyboardReturnEnabled: true,
    });
  });

  it("parses the legacy layout", async () => {
    const send = async (capdu: string) =>
      capdu === "0042000000" ? "010001000101FF9000" : "9000";
    const config = await readDeviceConfigData(send, "1.4.0");
    expect(config).toMatchObject({
      layout: "v1",
      ledOn: true,
      hotpOn: false,
      ndefReadonly: true,
      sigTouch: false,
      decTouch: true,
      autTouch: true,
      touchCacheTime: 255,
    });
  });

  it("sends the expected switch command", async () => {
    const commands: string[] = [];
    const send = async (capdu: string) => {
      commands.push(capdu);
      return "9000";
    };
    await setConfigSwitch(send, "123456", "keyboardReturn", true);
    expect(commands.at(-1)).toBe("00400601");
  });

  it("parses two-byte flash usage", async () => {
    const send = async (capdu: string) =>
      capdu === "0041000000" ? "0A149000" : "9000";
    await expect(readFlashUsage(send)).resolves.toEqual({
      usedKiB: 10,
      totalKiB: 20,
    });
  });
});
