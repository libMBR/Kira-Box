import { PasskeyError } from "./apdu";
import type { OathAlgorithm, OathType } from "./oath";

export interface OtpauthCredential {
  type: OathType;
  issuer: string;
  account: string;
  secret: string;
  algorithm: OathAlgorithm;
  digits: number;
  counter: number;
  period: number;
}

function decodeComponent(value: string, field: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new PasskeyError(
      `The ${field} in the otpauth URI is not valid percent-encoding.`,
      "OTPAUTH_ENCODING",
    );
  }
}

function parseInteger(
  value: string | null,
  field: string,
  fallback: number,
): number {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) {
    throw new PasskeyError(
      `The ${field} in the otpauth URI must be a number.`,
      "OTPAUTH_INVALID",
    );
  }
  return Number.parseInt(value, 10);
}

/**
 * Parses a Key URI Format string (`otpauth://totp/...`) into the fields the
 * OATH applet accepts. The applet always uses a 30-second TOTP period, so other
 * periods are rejected instead of silently producing different codes.
 */
export function parseOtpauthUri(input: string): OtpauthCredential {
  const raw = input.trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new PasskeyError(
      "Enter a valid otpauth:// URI.",
      "OTPAUTH_INVALID",
    );
  }

  if (url.protocol !== "otpauth:") {
    throw new PasskeyError(
      "The URI must start with otpauth://.",
      "OTPAUTH_INVALID",
    );
  }

  const type = url.hostname.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    throw new PasskeyError(
      `Unsupported otpauth type "${type}". Use totp or hotp.`,
      "OTPAUTH_INVALID",
    );
  }

  const segments = url.pathname.replace(/^\/+/, "").split("/");
  const rawLabel = segments[0] ?? "";
  if (!rawLabel) {
    throw new PasskeyError(
      "The otpauth URI is missing its label.",
      "OTPAUTH_INVALID",
    );
  }

  const label = decodeComponent(rawLabel, "label");
  const separator = label.indexOf(":");
  const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : "";
  const account = (separator >= 0 ? label.slice(separator + 1) : label).trim();
  if (!account) {
    throw new PasskeyError(
      "The otpauth URI is missing its account name.",
      "OTPAUTH_INVALID",
    );
  }

  const queryIssuer = url.searchParams.get("issuer");
  const issuer = (queryIssuer ?? labelIssuer).trim();

  const secret = (url.searchParams.get("secret") ?? "").replace(/\s+/g, "");
  if (!secret) {
    throw new PasskeyError(
      "The otpauth URI is missing its secret.",
      "OTPAUTH_MISSING_SECRET",
    );
  }

  const algorithm = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  if (algorithm !== "SHA1" && algorithm !== "SHA256") {
    throw new PasskeyError(
      `The device only supports SHA1 and SHA256, not ${algorithm}.`,
      "OTPAUTH_UNSUPPORTED_ALGORITHM",
    );
  }

  const digits = parseInteger(url.searchParams.get("digits"), "digits", 6);
  if (digits < 5 || digits > 8) {
    throw new PasskeyError(
      "The device only supports 5 to 8 digits.",
      "OTPAUTH_UNSUPPORTED_DIGITS",
    );
  }

  const period = parseInteger(url.searchParams.get("period"), "period", 30);
  if (type === "totp" && period !== 30) {
    throw new PasskeyError(
      `The device only supports a 30-second TOTP period, not ${period}.`,
      "OTPAUTH_UNSUPPORTED_PERIOD",
    );
  }

  const counter = parseInteger(url.searchParams.get("counter"), "counter", 0);

  return {
    type,
    issuer,
    account,
    secret: secret.toUpperCase(),
    algorithm: algorithm === "SHA256" ? "sha256" : "sha1",
    digits,
    counter,
    period,
  };
}

export function credentialName(issuer: string, account: string): string {
  return issuer ? `${issuer}:${account}` : account;
}
