import {
  assertSuccess,
  buildApdu,
  bytesToHex,
  concatBytes,
  hexToBytes,
  PasskeyError,
  responseData,
  utf8Decode,
  utf8Encode,
  type SendApdu,
} from "./apdu";
import { deriveOathKey, hmacSha1 } from "./crypto";
import { encodeTlv, findTlv, parseTlv } from "./tlv";

export const OATH_AID = "A0000005272101";
export const OATH_PASSWORD_REQUIRED = "OATH_PASSWORD_REQUIRED";

export type OathProtocol = "legacy" | "v1";
export type OathType = "totp" | "hotp";
export type OathAlgorithm = "sha1" | "sha256";

export interface OathState {
  protocol: OathProtocol;
  salt: Uint8Array | null;
  challenge: Uint8Array | null;
  requiresPassword: boolean;
}

export interface OathCredential {
  name: string;
  type: OathType;
  code: string;
  requireTouch: boolean;
}

export interface OathAddInput {
  name: string;
  key: Uint8Array;
  type: OathType;
  algorithm: OathAlgorithm;
  digits: number;
  counter: number;
  requireTouch: boolean;
}

export interface OathLoadResult {
  state: OathState;
  credentials: OathCredential[];
}

function chainFor(protocol: OathProtocol): (sw2: string) => string {
  return protocol === "v1"
    ? (sw2) => `00A50000${sw2}`
    : (sw2) => `00060000${sw2}`;
}

export async function selectOath(send: SendApdu): Promise<OathState> {
  const response = await send(`00A4040007${OATH_AID}`);
  if (response === "9000") {
    return {
      protocol: "legacy",
      salt: null,
      challenge: null,
      requiresPassword: false,
    };
  }
  assertSuccess(response);
  const tlv = parseTlv(responseData(response));
  const version = findTlv(tlv, 0x79)?.value;
  if (!version) {
    throw new PasskeyError(
      "The device does not expose the supported TOTP/HOTP application.",
      "OATH_UNSUPPORTED",
    );
  }
  const salt = findTlv(tlv, 0x71)?.value ?? null;
  const challenge = findTlv(tlv, 0x74)?.value ?? null;
  return {
    protocol: "v1",
    salt,
    challenge,
    requiresPassword: challenge !== null,
  };
}

async function authenticate(
  send: SendApdu,
  state: OathState,
  password: string,
): Promise<void> {
  if (!state.requiresPassword) return;
  if (!state.salt || !state.challenge) {
    throw new PasskeyError(
      "The device requires a password but did not provide a challenge.",
      "OATH_CHALLENGE",
    );
  }
  const { key } = await deriveOathKey(password, state.salt);
  const mac = await hmacSha1(key, state.challenge);
  const response = await send(`00A300001C7514${bytesToHex(mac)}740400000000`);
  assertSuccess(response);
}

export async function prepareOath(
  send: SendApdu,
  password: string,
): Promise<OathState> {
  const state = await selectOath(send);
  if (state.requiresPassword && password.length === 0) {
    throw new PasskeyError(
      "This device requires an OATH password.",
      OATH_PASSWORD_REQUIRED,
    );
  }
  await authenticate(send, state, password);
  return state;
}

function currentChallengeHex(): string {
  return Math.floor(Date.now() / 30000)
    .toString(16)
    .padStart(16, "0");
}

export function parseOathCode(value: Uint8Array): string {
  if (value.length < 5) {
    throw new PasskeyError("The device returned an incomplete code.", "OATH_CODE");
  }
  const digits = value[0] ?? 0;
  if (digits < 1 || digits > 8) {
    throw new PasskeyError("The device returned an unsupported code length.", "OATH_DIGITS");
  }
  const raw =
    (((value[1] ?? 0) << 24) >>> 0) +
    ((value[2] ?? 0) << 16) +
    ((value[3] ?? 0) << 8) +
    (value[4] ?? 0);
  const code = raw % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

export function parseOathEntries(data: Uint8Array): OathCredential[] {
  const entries: OathCredential[] = [];
  let current: OathCredential | null = null;
  for (const item of parseTlv(data)) {
    if (item.tag === 0x71) {
      if (current) entries.push(current);
      current = {
        name: utf8Decode(item.value),
        type: "totp",
        code: "",
        requireTouch: false,
      };
      continue;
    }
    if (!current) {
      throw new PasskeyError("The device returned an unexpected TOTP/HOTP entry.", "OATH_ENTRY");
    }
    if (item.tag === 0x76) {
      current.code = parseOathCode(item.value);
    } else if (item.tag === 0x77) {
      current.type = "hotp";
    } else if (item.tag === 0x7c) {
      current.requireTouch = true;
    } else if (item.tag === 0x75 && item.value.length > 0) {
      current.type = ((item.value[0] ?? 0) >> 4) === 1 ? "hotp" : "totp";
    }
  }
  if (current) entries.push(current);
  return entries;
}

export async function loadOathCredentials(
  send: SendApdu,
  password: string,
): Promise<OathLoadResult> {
  const state = await prepareOath(send, password);
  const challenge = currentChallengeHex();
  const command =
    state.protocol === "v1"
      ? `00A400010A7408${challenge}`
      : `000500000A7408${challenge}`;
  const response = await send(command, chainFor(state.protocol));
  assertSuccess(response);
  return {
    state,
    credentials: parseOathEntries(responseData(response)),
  };
}

export async function calculateOathCode(
  send: SendApdu,
  password: string,
  name: string,
  type: OathType,
): Promise<string> {
  const state = await prepareOath(send, password);
  const nameBytes = utf8Encode(name);
  const parts: Uint8Array[] = [encodeTlv(0x71, nameBytes)];
  if (type === "totp") {
    parts.push(encodeTlv(0x74, hexToBytes(currentChallengeHex())));
  }
  const data = concatBytes(...parts);
  const response = await send(
    state.protocol === "v1"
      ? buildApdu(0xa2, 0x00, 0x01, data)
      : buildApdu(0x04, 0x00, 0x00, data),
    chainFor(state.protocol),
  );
  assertSuccess(response);
  const code = findTlv(parseTlv(responseData(response)), 0x76)?.value;
  if (!code) {
    throw new PasskeyError("The device did not return a code.", "OATH_CODE");
  }
  return parseOathCode(code);
}

export async function addOathCredential(
  send: SendApdu,
  password: string,
  input: OathAddInput,
): Promise<void> {
  const nameBytes = utf8Encode(input.name);
  if (nameBytes.length === 0 || nameBytes.length > 64) {
    throw new PasskeyError("The account name must be 1 to 64 UTF-8 bytes.", "INVALID_NAME");
  }
  if (input.key.length === 0 || input.key.length > 32) {
    throw new PasskeyError("The secret must be 1 to 32 bytes.", "INVALID_SECRET");
  }
  if (!Number.isInteger(input.digits) || input.digits < 5 || input.digits > 8) {
    throw new PasskeyError("Digits must be between 5 and 8.", "INVALID_DIGITS");
  }
  if (input.type === "hotp") {
    if (
      !Number.isInteger(input.counter) ||
      input.counter < 0 ||
      input.counter > 0xffffffff
    ) {
      throw new PasskeyError(
        "The counter must be between 0 and 4294967295.",
        "INVALID_COUNTER",
      );
    }
  }
  const typeFlag = input.type === "hotp" ? 0x10 : 0x20;
  const algorithmFlag = input.algorithm === "sha256" ? 0x02 : 0x01;
  const parts: Uint8Array[] = [
    encodeTlv(0x71, nameBytes),
    encodeTlv(
      0x73,
      new Uint8Array([typeFlag | algorithmFlag, input.digits, ...input.key]),
    ),
  ];
  const state = await prepareOath(send, password);
  if (input.requireTouch) {
    // v1 applets encode the property as tag + value; legacy applets use a
    // length-prefixed TLV. Sending the v1 form a length byte makes the
    // credential land in a different slot, so choose by protocol.
    parts.push(
      state.protocol === "v1"
        ? new Uint8Array([0x78, 0x02])
        : encodeTlv(0x78, new Uint8Array([0x02])),
    );
  }
  if (input.type === "hotp" && input.counter > 0) {
    parts.push(
      encodeTlv(
        0x7a,
        new Uint8Array([
          (input.counter >>> 24) & 0xff,
          (input.counter >>> 16) & 0xff,
          (input.counter >>> 8) & 0xff,
          input.counter & 0xff,
        ]),
      ),
    );
  }
  assertSuccess(await send(buildApdu(0x01, 0x00, 0x00, concatBytes(...parts))));
}

export async function deleteOathCredential(
  send: SendApdu,
  password: string,
  name: string,
): Promise<void> {
  await prepareOath(send, password);
  assertSuccess(
    await send(buildApdu(0x02, 0x00, 0x00, encodeTlv(0x71, utf8Encode(name)))),
  );
}

export async function setDefaultOathCredential(
  send: SendApdu,
  password: string,
  name: string,
): Promise<void> {
  await prepareOath(send, password);
  assertSuccess(
    await send(buildApdu(0x55, 0x00, 0x00, encodeTlv(0x71, utf8Encode(name)))),
  );
}

export async function setOathPassword(
  send: SendApdu,
  newPassword: string,
): Promise<void> {
  const state = await selectOath(send);
  if (state.protocol !== "v1" || !state.salt) {
    throw new PasskeyError(
      "This device does not support an OATH password.",
      "OATH_PASSWORD_UNSUPPORTED",
    );
  }
  if (newPassword.length === 0) {
    assertSuccess(await send("00030000027300"));
    return;
  }
  const { key, bytes } = await deriveOathKey(newPassword, state.salt);
  const mac = await hmacSha1(key, new Uint8Array([0, 0, 0, 0]));
  const data = concatBytes(
    encodeTlv(0x73, new Uint8Array([0x01, ...bytes])),
    encodeTlv(0x74, new Uint8Array([0, 0, 0, 0])),
    encodeTlv(0x75, mac),
  );
  assertSuccess(await send(buildApdu(0x03, 0x00, 0x00, data)));
}
