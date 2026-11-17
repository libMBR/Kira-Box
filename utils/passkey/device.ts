import {
  assertSuccess,
  buildApdu,
  bytesToHex,
  describeStatus,
  PasskeyError,
  pinErrorMessage,
  responseData,
  isSuccess,
  utf8Decode,
  utf8Encode,
  type SendApdu,
} from "./apdu";

export const ADMIN_AID = "F000000000";
// Only these hardware families are allowed to proceed. Extend the list only
// after verifying the device command set.
export const SUPPORTED_MODEL_PREFIXES = ["USRKEY"];
export const MAX_SUPPORTED_MAJOR_VERSION = 2;

export interface DeviceInfo {
  firmwareVersion: string;
  model: string;
  serialNumber: string;
  chipId: string;
}

export interface FlashUsage {
  usedKiB: number;
  totalKiB: number;
}

export interface DeviceConfig {
  layout: "v1" | "v2";
  ledOn: boolean;
  hotpOn: boolean;
  ndefReadonly: boolean;
  ndefEnabled: boolean;
  webusbLandingEnabled: boolean;
  keyboardReturnEnabled: boolean;
  sigTouch: boolean;
  decTouch: boolean;
  autTouch: boolean;
  touchCacheTime: number;
}

export type ConfigSwitch =
  | "led"
  | "hotp"
  | "ndefReadonly"
  | "ndefEnabled"
  | "webusbLanding"
  | "keyboardReturn"
  | "sigTouch"
  | "decTouch"
  | "autTouch";

export type Applet = "openpgp" | "piv" | "oath" | "ndef";

const APPLET_RESET_COMMANDS: Record<Applet, string> = {
  openpgp: "00030000",
  piv: "00040000",
  oath: "00050000",
  ndef: "00070000",
};

function versionParts(version: string): number[] | null {
  const match = version.trim().match(/\d+(?:\.\d+)*/);
  if (!match) return null;
  return match[0].split(".").map((part) => Number.parseInt(part, 10));
}

export function compareVersions(left: string, right: string): number {
  const a = versionParts(left) ?? [];
  const b = versionParts(right) ?? [];
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function isLegacyFirmware(version: string): boolean {
  // Custom firmware reports a build ID instead of a semantic version. The
  // supported hardware family uses the newer configuration layout.
  if (isBuildVersion(version)) return false;
  return compareVersions(version, "1.5.0") < 0;
}

function isBuildVersion(version: string): boolean {
  return /^[0-9a-f]{7,40}(?:-latest)?$/i.test(version.trim());
}

export function validateDeviceInfo(info: DeviceInfo):
  | { ok: true }
  | { ok: false; reason: string } {
  const model = info.model.trim();
  const supported = SUPPORTED_MODEL_PREFIXES.some((prefix) =>
    model.toLowerCase().startsWith(prefix.toLowerCase()),
  );
  if (!supported) {
    return {
      ok: false,
      reason: `Unsupported hardware "${model || "unknown"}".`,
    };
  }
  const parts = versionParts(info.firmwareVersion);
  if (!parts || parts.length === 0) {
    return {
      ok: false,
      reason: `Unable to read the firmware version ("${info.firmwareVersion}").`,
    };
  }
  if (
    !isBuildVersion(info.firmwareVersion) &&
    (parts[0] ?? 0) > MAX_SUPPORTED_MAJOR_VERSION
  ) {
    // Build IDs are accepted because the model allowlist above already limits
    // the tool to the supported hardware family.
    return {
      ok: false,
      reason: `Firmware ${info.firmwareVersion} is newer than this tool supports.`,
    };
  }
  return { ok: true };
}

export async function selectAdmin(send: SendApdu): Promise<void> {
  assertSuccess(await send(`00A4040005${ADMIN_AID}`));
}

async function readAdminString(send: SendApdu, p1: string): Promise<string> {
  const response = await send(`0031${p1}0000`);
  assertSuccess(response);
  return utf8Decode(responseData(response)).trim();
}

async function readAdminHex(send: SendApdu, p1: string): Promise<string> {
  const response = await send(`0032${p1}0000`);
  assertSuccess(response);
  return bytesToHex(responseData(response));
}

export async function readDeviceInfo(send: SendApdu): Promise<DeviceInfo> {
  await selectAdmin(send);
  return {
    firmwareVersion: await readAdminString(send, "00"),
    model: await readAdminString(send, "01"),
    serialNumber: await readAdminHex(send, "00"),
    chipId: await readAdminHex(send, "01"),
  };
}

export async function readFlashUsage(send: SendApdu): Promise<FlashUsage> {
  const response = await send("0041000000");
  assertSuccess(response);
  const data = responseData(response);
  if (data.length < 2) {
    throw new PasskeyError(
      "The device returned incomplete flash usage.",
      "FLASH_USAGE_SHORT",
    );
  }
  return {
    usedKiB: data[0] ?? 0,
    totalKiB: data[1] ?? 0,
  };
}

export async function verifyAdminPin(send: SendApdu, pin: string): Promise<void> {
  const response = await send(
    buildApdu(0x20, 0x00, 0x00, utf8Encode(pin)),
  );
  if (!isSuccess(response)) {
    throw new PasskeyError(
      pinErrorMessage(response.slice(-4)),
      response.slice(-4),
    );
  }
}

export async function readDeviceConfigData(
  send: SendApdu,
  firmwareVersion: string,
): Promise<DeviceConfig> {
  const response = await send("0042000000");
  assertSuccess(response);
  const data = responseData(response);
  const legacy = isLegacyFirmware(firmwareVersion);
  if (legacy) {
    if (data.length < 7) {
      throw new PasskeyError("The device returned an incomplete configuration.", "CONFIG_SHORT");
    }
    return {
      layout: "v1",
      ledOn: data[0] === 1,
      hotpOn: data[1] === 1,
      ndefReadonly: data[2] === 1,
      ndefEnabled: false,
      webusbLandingEnabled: false,
      keyboardReturnEnabled: false,
      sigTouch: data[3] === 1,
      decTouch: data[4] === 1,
      autTouch: data[5] === 1,
      touchCacheTime: data[6] ?? 0,
    };
  }
  if (data.length < 6) {
    throw new PasskeyError("The device returned an incomplete configuration.", "CONFIG_SHORT");
  }
  return {
    layout: "v2",
    ledOn: data[0] === 1,
    hotpOn: data[1] === 1,
    ndefReadonly: data[2] === 1,
    ndefEnabled: data[3] === 1,
    webusbLandingEnabled: data[4] === 1,
    keyboardReturnEnabled: data[5] === 1,
    sigTouch: false,
    decTouch: false,
    autTouch: false,
    touchCacheTime: 0,
  };
}

function switchApdu(key: ConfigSwitch, enabled: boolean): string {
  const flag = enabled ? "01" : "00";
  switch (key) {
    case "led":
      return `004001${flag}`;
    case "hotp":
      return `004003${flag}`;
    case "ndefReadonly":
      return `0008${flag}00`;
    case "ndefEnabled":
      return `004004${flag}`;
    case "webusbLanding":
      return `004005${flag}`;
    case "keyboardReturn":
      return `004006${flag}`;
    case "sigTouch":
      return `000900${flag}`;
    case "decTouch":
      return `000901${flag}`;
    case "autTouch":
      return `000902${flag}`;
  }
}

export async function setConfigSwitch(
  send: SendApdu,
  pin: string,
  key: ConfigSwitch,
  enabled: boolean,
): Promise<void> {
  await selectAdmin(send);
  await verifyAdminPin(send, pin);
  assertSuccess(await send(switchApdu(key, enabled)));
}

export async function setTouchCacheTime(
  send: SendApdu,
  pin: string,
  seconds: number,
): Promise<void> {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 255) {
    throw new PasskeyError("Cache time must be between 0 and 255 seconds.", "INVALID_VALUE");
  }
  await selectAdmin(send);
  await verifyAdminPin(send, pin);
  assertSuccess(
    await send(`000903${seconds.toString(16).padStart(2, "0")}`),
  );
}

export async function changeAdminPin(
  send: SendApdu,
  oldPin: string,
  newPin: string,
): Promise<void> {
  if (newPin.length < 6 || newPin.length > 64) {
    throw new PasskeyError("The new PIN must be 6 to 64 characters.", "INVALID_PIN");
  }
  await selectAdmin(send);
  await verifyAdminPin(send, oldPin);
  assertSuccess(
    await send(buildApdu(0x21, 0x00, 0x00, utf8Encode(newPin))),
  );
}

export async function resetApplet(
  send: SendApdu,
  pin: string,
  applet: Applet,
): Promise<void> {
  await selectAdmin(send);
  await verifyAdminPin(send, pin);
  assertSuccess(await send(APPLET_RESET_COMMANDS[applet]));
}

export async function factoryReset(send: SendApdu): Promise<void> {
  await selectAdmin(send);
  const response = await send(`0050000005${bytesToHex(utf8Encode("RESET"))}`);
  const sw = response.slice(-4);
  if (sw === "9000") return;
  if (sw === "6985") {
    throw new PasskeyError(
      "The device is not ready to reset. Use up the Admin PIN retries first, then try again.",
      sw,
    );
  }
  if (sw === "6982") {
    throw new PasskeyError(
      "The device did not detect a touch. Start the reset again and touch the device while it flashes.",
      sw,
    );
  }
  throw new PasskeyError(describeStatus(sw), sw);
}

export async function repairNfc(send: SendApdu, pin: string): Promise<void> {
  await selectAdmin(send);
  await verifyAdminPin(send, pin);
  assertSuccess(await send("00FF01000603A044000420"));
  assertSuccess(await send("00FF01000903B005720300B39900"));
}
