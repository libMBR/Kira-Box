export type SendApdu = (
  capdu: string,
  chain?: (sw2: string) => string,
) => Promise<string>;

export class PasskeyError extends Error {
  code?: string;

  constructor(message: string, code?: string) {
    super(message);
    this.name = "PasskeyError";
    this.code = code;
  }
}

const HEX_PATTERN = /^[0-9a-f]*$/i;

export function hexToBytes(value: string): Uint8Array {
  const hex = value.replace(/\s+/g, "");
  if (hex.length % 2 !== 0 || !HEX_PATTERN.test(hex)) {
    throw new PasskeyError("Invalid hexadecimal data.", "INVALID_HEX");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(value: ArrayLike<number>): string {
  let result = "";
  for (let i = 0; i < value.length; i++) {
    result += (value[i] ?? 0).toString(16).padStart(2, "0");
  }
  return result.toUpperCase();
}

export function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function utf8Decode(value: Uint8Array): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === 0) end--;
  return new TextDecoder().decode(value.subarray(0, end));
}

export function concatBytes(...parts: ArrayLike<number>[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function byteHex(value: number): string {
  return value.toString(16).padStart(2, "0").toUpperCase();
}

export function buildApdu(
  ins: number,
  p1: number,
  p2: number,
  data: Uint8Array = new Uint8Array(),
  le?: string,
): string {
  if (data.length > 255) {
    throw new PasskeyError("APDU data is too long.", "APDU_TOO_LONG");
  }
  const header = `00${byteHex(ins)}${byteHex(p1)}${byteHex(p2)}`;
  const body = data.length > 0 ? `${byteHex(data.length)}${bytesToHex(data)}` : "";
  return `${header}${body}${le ?? ""}`;
}

export function statusWord(rapdu: string): string {
  return rapdu.slice(-4).toUpperCase();
}

export function responseData(rapdu: string): Uint8Array {
  return hexToBytes(rapdu.slice(0, -4));
}

export function isSuccess(rapdu: string): boolean {
  return statusWord(rapdu) === "9000";
}

export function describeStatus(sw: string): string {
  switch (sw) {
    case "9000":
      return "Success.";
    case "6982":
      return "Authentication required. Verify the PIN first.";
    case "6983":
      return "The PIN is locked.";
    case "6985":
      return "The device refused the operation because its conditions were not met.";
    case "6700":
      return "The device rejected the data length.";
    case "6A80":
      return "The device rejected the data.";
    case "6A82":
      return "The application was not found on the device.";
    case "6A86":
      return "The device rejected the command parameters.";
    case "6A88":
      return "The requested data was not found.";
    case "6D00":
      return "This command is not supported by the device.";
    case "6E00":
      return "This command class is not supported by the device.";
    case "6600":
      return "Touch confirmation timed out.";
    case "6F00":
      return "The device reported an unspecified error.";
    default:
      if (sw.startsWith("63C")) {
        const retries = Number.parseInt(sw.slice(3), 16);
        return `Verification failed. ${retries} attempt${retries === 1 ? "" : "s"} remaining.`;
      }
      if (sw.startsWith("61")) {
        return "More data is available.";
      }
      return `The device returned status ${sw}.`;
  }
}

export function assertSuccess(rapdu: string): void {
  const sw = statusWord(rapdu);
  if (sw !== "9000") {
    throw new PasskeyError(describeStatus(sw), sw);
  }
}

export function pinErrorMessage(sw: string): string {
  switch (sw) {
    case "6983":
      return "The PIN is locked.";
    case "6982":
      return "The PIN is incorrect.";
    case "6700":
      return "The PIN length is invalid.";
    default:
      if (sw.startsWith("63C")) {
        const retries = Number.parseInt(sw.slice(3), 16);
        return `The PIN is incorrect. ${retries} attempt${retries === 1 ? "" : "s"} remaining.`;
      }
      return describeStatus(sw);
  }
}
