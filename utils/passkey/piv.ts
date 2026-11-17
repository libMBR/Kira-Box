import {
  assertSuccess,
  buildApdu,
  bytesToHex,
  byteHex,
  concatBytes,
  hexToBytes,
  PasskeyError,
  pinErrorMessage,
  responseData,
  statusWord,
  utf8Encode,
  type SendApdu,
} from "./apdu";
import { tripleDesEncryptBlock } from "./des";
import { encodeTlv, findTlv, parseTlv } from "./tlv";

export const PIV_AID = "A000000308";

export type PivPinKind = "pin" | "puk";

export type PivSlot = "9a" | "9c" | "9d" | "9e";

export interface PivSlotInfo {
  id: PivSlot;
  label: string;
  container: string;
}

export const PIV_SLOTS: Record<PivSlot, PivSlotInfo> = {
  "9a": { id: "9a", label: "Authentication (9A)", container: "5FC105" },
  "9c": { id: "9c", label: "Digital signature (9C)", container: "5FC101" },
  "9d": { id: "9d", label: "Key management (9D)", container: "5FC10A" },
  "9e": { id: "9e", label: "Card authentication (9E)", container: "5FC10B" },
};

export type PivAlgorithm = "rsa2048" | "p256" | "p384";

export interface PivAlgorithmInfo {
  label: string;
  code: number;
}

export const PIV_ALGORITHMS: Record<PivAlgorithm, PivAlgorithmInfo> = {
  rsa2048: { label: "RSA 2048", code: 0x07 },
  p256: { label: "ECC P-256", code: 0x11 },
  p384: { label: "ECC P-384", code: 0x14 },
};

const RSA_OID = "2A864886F70D010101";
const EC_OID = "2A8648CE3D0201";
const P256_OID = "2A8648CE3D030107";
const P384_OID = "2B81040022";

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function paddedPin(pin: string): Uint8Array {
  const encoded = utf8Encode(pin);
  if (encoded.length > 8) {
    throw new PasskeyError(
      "PIV reference data cannot exceed 8 bytes.",
      "INVALID_PIN",
    );
  }
  const bytes = new Uint8Array(8);
  bytes.fill(0xff);
  bytes.set(encoded, 0);
  return bytes;
}

export function parsePivManagementKey(value: string): Uint8Array {
  const hex = value.replace(/[\s:-]/g, "");
  if (!/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48})$/.test(hex)) {
    throw new PasskeyError(
      "The management key must be 32 or 48 hexadecimal characters (16 or 24 bytes).",
      "PIV_MK_FORMAT",
    );
  }
  return hexToBytes(hex);
}

export async function selectPiv(send: SendApdu): Promise<void> {
  assertSuccess(await send(`00A4040005${PIV_AID}`));
}

export async function verifyPivPin(
  send: SendApdu,
  pin: string,
): Promise<void> {
  await selectPiv(send);
  const rapdu = await send(buildApdu(0x20, 0x00, 0x80, paddedPin(pin)));
  const sw = statusWord(rapdu);
  if (sw !== "9000") {
    throw new PasskeyError(pinErrorMessage(sw), sw);
  }
}

// Extended-length APDU with a three-byte Lc, as used by the reference
// implementation for PIV data objects that do not fit in a short APDU.
function extendedApdu(
  ins: number,
  p1: number,
  p2: number,
  data: Uint8Array,
): string {
  if (data.length > 0xffff) {
    throw new PasskeyError(
      "The PIV data object is too large for one command.",
      "PIV_DATA_LENGTH",
    );
  }
  return `00${byteHex(ins)}${byteHex(p1)}${byteHex(p2)}${data.length
    .toString(16)
    .padStart(6, "0")}${bytesToHex(data)}`;
}

function challengeFrom(rapdu: string): Uint8Array {
  const outer = findTlv(parseTlv(responseData(rapdu)), 0x7c);
  const challenge = outer
    ? findTlv(parseTlv(outer.value), 0x81)
    : undefined;
  if (!challenge || challenge.value.length !== 8) {
    throw new PasskeyError(
      "The device returned an unexpected authentication challenge.",
      "PIV_CHALLENGE",
    );
  }
  return challenge.value;
}

// Requires the PIV application to be selected. SELECT resets the security
// status, so this is always run immediately before the protected operation.
async function authenticateSelected(
  send: SendApdu,
  key: Uint8Array,
): Promise<void> {
  if (key.length !== 16 && key.length !== 24) {
    throw new PasskeyError(
      "The management key must be 16 or 24 bytes.",
      "PIV_MK_LENGTH",
    );
  }
  const challengeRapdu = await send("0087009B047C02810000");
  assertSuccess(challengeRapdu);
  const cryptogram = tripleDesEncryptBlock(challengeFrom(challengeRapdu), key);
  const data = concatBytes([0x7c, 0x0a, 0x82, 0x08], cryptogram);
  assertSuccess(await send(buildApdu(0x87, 0x00, 0x9b, data)));
}

export async function authenticatePivManagementKey(
  send: SendApdu,
  key: Uint8Array,
): Promise<void> {
  await selectPiv(send);
  await authenticateSelected(send, key);
}

export async function changePivManagementKey(
  send: SendApdu,
  currentKey: Uint8Array,
  newKey: Uint8Array,
): Promise<void> {
  if (newKey.length !== 24) {
    throw new PasskeyError(
      "The new management key must be 24 bytes (48 hex digits).",
      "PIV_MK_LENGTH",
    );
  }
  await selectPiv(send);
  await authenticateSelected(send, currentKey);
  assertSuccess(
    await send(
      buildApdu(
        0xff,
        0xff,
        0xff,
        concatBytes([0x03, 0x9b, 0x18], newKey),
      ),
    ),
  );
}

export async function changePivPin(
  send: SendApdu,
  kind: PivPinKind,
  oldPin: string,
  newPin: string,
): Promise<void> {
  const oldBytes = paddedPin(oldPin);
  const newBytes = paddedPin(newPin);
  await selectPiv(send);
  assertSuccess(
    await send(
      buildApdu(
        0x24,
        0x00,
        kind === "pin" ? 0x80 : 0x81,
        new Uint8Array([...oldBytes, ...newBytes]),
      ),
    ),
  );
}

function unwrapCertificate(data: Uint8Array): Uint8Array {
  if (data[0] !== 0x53 || data.length < 2) return data;
  const first = data[1]!;
  if (first < 0x80) {
    return data.length >= 2 + first ? data.subarray(2, 2 + first) : data;
  }
  if (first === 0x81 && data.length >= 3) {
    const length = data[2]!;
    return data.length >= 3 + length ? data.subarray(3, 3 + length) : data;
  }
  if (first === 0x82 && data.length >= 4) {
    const length = (data[2]! << 8) | data[3]!;
    return data.length >= 4 + length ? data.subarray(4, 4 + length) : data;
  }
  return data;
}

export function validatePivCertificate(certificate: Uint8Array): void {
  if (certificate.length < 2 || certificate[0] !== 0x30) {
    throw new PasskeyError(
      "The file is not a DER-encoded X.509 certificate.",
      "PIV_CERT_FORMAT",
    );
  }
  const first = certificate[1]!;
  let headerLength = 2;
  let length = first;
  if ((first & 0x80) !== 0) {
    const count = first & 0x7f;
    if (count === 0 || count > 3 || certificate.length < 2 + count) {
      throw new PasskeyError(
        "The certificate has an invalid DER length.",
        "PIV_CERT_FORMAT",
      );
    }
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + certificate[2 + i]!;
    }
    headerLength = 2 + count;
  }
  if (headerLength + length !== certificate.length) {
    throw new PasskeyError(
      "The certificate has an invalid DER length.",
      "PIV_CERT_FORMAT",
    );
  }
}

function base64Decode(text: string): Uint8Array {
  const clean = text.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    throw new PasskeyError(
      "The PEM data contains invalid base64.",
      "PIV_PEM_FORMAT",
    );
  }
  const bytes = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of clean) {
    const value = BASE64_ALPHABET.indexOf(character);
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = (buffer >> bits) & 0xff;
    }
  }
  return bytes.subarray(0, offset);
}

export function decodePivCertificate(input: Uint8Array): Uint8Array {
  const head = new TextDecoder().decode(
    input.subarray(0, Math.min(input.length, 64)),
  );
  if (!head.includes("-----BEGIN")) {
    return input;
  }
  const text = new TextDecoder().decode(input);
  const body = text.match(
    /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/,
  );
  if (!body || !body[1]) {
    throw new PasskeyError(
      "The PEM data does not contain a certificate.",
      "PIV_PEM_FORMAT",
    );
  }
  return base64Decode(body[1].replace(/\s+/g, ""));
}

export async function readPivCertificate(
  send: SendApdu,
  slot: PivSlot,
): Promise<Uint8Array | null> {
  await selectPiv(send);
  const rapdu = await send(`00CB3FFF0000055C03${PIV_SLOTS[slot].container}`);
  const sw = statusWord(rapdu);
  if (sw === "6A88" || sw === "6A82") {
    return null;
  }
  assertSuccess(rapdu);
  const data = responseData(rapdu);
  if (data.length === 0) return null;
  const certificate = unwrapCertificate(data);
  return certificate.length === 0 ? null : certificate;
}

export async function writePivCertificate(
  send: SendApdu,
  slot: PivSlot,
  certificate: Uint8Array,
  managementKey: Uint8Array,
): Promise<void> {
  validatePivCertificate(certificate);
  if (certificate.length > 0xffff) {
    throw new PasskeyError(
      "The certificate is too large for a PIV data object.",
      "PIV_CERT_LENGTH",
    );
  }
  await selectPiv(send);
  await authenticateSelected(send, managementKey);
  const body = concatBytes(
    [0x5c, 0x03],
    hexToBytes(PIV_SLOTS[slot].container),
    [0x53, 0x82, (certificate.length >> 8) & 0xff, certificate.length & 0xff],
    certificate,
  );
  assertSuccess(await send(extendedApdu(0xdb, 0x3f, 0xff, body)));
}

export async function deletePivCertificate(
  send: SendApdu,
  slot: PivSlot,
  managementKey: Uint8Array,
): Promise<void> {
  await selectPiv(send);
  await authenticateSelected(send, managementKey);
  const body = encodeTlv(0x5c, hexToBytes(PIV_SLOTS[slot].container));
  assertSuccess(await send(buildApdu(0xdb, 0x3f, 0xff, body)));
}

export interface PivGeneratedKey {
  algorithm: PivAlgorithm;
  publicKey: string;
  summary: string;
}

function parseGeneratedPublicKey(
  data: Uint8Array,
  algorithm: PivAlgorithm,
): PivGeneratedKey {
  const outer = findTlv(parseTlv(data), 0x7f49);
  if (!outer) {
    throw new PasskeyError(
      "The device did not return a public key.",
      "PIV_KEY_PARSE",
    );
  }
  const fields = parseTlv(outer.value);
  if (algorithm === "rsa2048") {
    const modulus = findTlv(fields, 0x81);
    const exponent = findTlv(fields, 0x82);
    if (!modulus || !exponent) {
      throw new PasskeyError(
        "The device returned an unexpected RSA public key.",
        "PIV_KEY_PARSE",
      );
    }
    return {
      algorithm,
      publicKey: bytesToHex(modulus.value),
      summary: `RSA 2048, public exponent ${bytesToHex(exponent.value)}`,
    };
  }
  const point = findTlv(fields, 0x86);
  if (!point) {
    throw new PasskeyError(
      "The device returned an unexpected EC public key.",
      "PIV_KEY_PARSE",
    );
  }
  return {
    algorithm,
    publicKey: bytesToHex(point.value),
    summary: `${PIV_ALGORITHMS[algorithm].label} public point, ${point.value.length} bytes`,
  };
}

export async function generatePivKey(
  send: SendApdu,
  slot: PivSlot,
  algorithm: PivAlgorithm,
  managementKey: Uint8Array,
): Promise<PivGeneratedKey> {
  await selectPiv(send);
  await authenticateSelected(send, managementKey);
  const template = encodeTlv(
    0xac,
    new Uint8Array([0x80, 0x01, PIV_ALGORITHMS[algorithm].code]),
  );
  const rapdu = await send(
    extendedApdu(0x47, 0x00, Number.parseInt(slot, 16), template),
  );
  assertSuccess(rapdu);
  return parseGeneratedPublicKey(responseData(rapdu), algorithm);
}

interface DerValue {
  tag: number;
  value: Uint8Array;
  next: number;
}

function readDerLength(
  data: Uint8Array,
  offset: number,
): { length: number; next: number } {
  if (offset >= data.length) {
    throw new PasskeyError(
      "The private key DER data is truncated.",
      "PIV_KEY_DER",
    );
  }
  const first = data[offset]!;
  if ((first & 0x80) === 0) {
    return { length: first, next: offset + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 3 || offset + count >= data.length) {
    throw new PasskeyError(
      "The private key DER data has an invalid length.",
      "PIV_KEY_DER",
    );
  }
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = length * 256 + data[offset + 1 + i]!;
  }
  return { length, next: offset + 1 + count };
}

function readDerValue(data: Uint8Array, offset: number): DerValue {
  if (offset >= data.length) {
    throw new PasskeyError(
      "The private key DER data is truncated.",
      "PIV_KEY_DER",
    );
  }
  const tag = data[offset]!;
  if ((tag & 0x1f) === 0x1f) {
    throw new PasskeyError(
      "The private key uses an unsupported DER encoding.",
      "PIV_KEY_DER",
    );
  }
  const length = readDerLength(data, offset + 1);
  const end = length.next + length.length;
  if (end > data.length) {
    throw new PasskeyError(
      "The private key DER data is truncated.",
      "PIV_KEY_DER",
    );
  }
  return { tag, value: data.subarray(length.next, end), next: end };
}

function derChildren(value: Uint8Array): DerValue[] {
  const children: DerValue[] = [];
  let offset = 0;
  while (offset < value.length) {
    const child = readDerValue(value, offset);
    children.push(child);
    offset = child.next;
  }
  return children;
}

function derIntegerBytes(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  return value.subarray(start);
}

function leftPad(value: Uint8Array, length: number): Uint8Array {
  if (value.length > length) {
    throw new PasskeyError(
      "The private key component is longer than expected.",
      "PIV_KEY_LENGTH",
    );
  }
  if (value.length === length) return value;
  const padded = new Uint8Array(length);
  padded.set(value, length - value.length);
  return padded;
}

function bigIntFromBytes(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

export interface PivRsaPrivateKey {
  kind: "rsa";
  p: Uint8Array;
  q: Uint8Array;
  dp: Uint8Array;
  dq: Uint8Array;
  qInv: Uint8Array;
}

export interface PivEccPrivateKey {
  kind: "ecc";
  curve: "p256" | "p384";
  scalar: Uint8Array;
}

export type PivPrivateKey = PivRsaPrivateKey | PivEccPrivateKey;

function parseRsaPrivateKey(children: DerValue[]): PivRsaPrivateKey {
  if (
    children.length < 9 ||
    children.slice(0, 9).some((node) => node.tag !== 0x02)
  ) {
    throw new PasskeyError(
      "The RSA private key is malformed.",
      "PIV_KEY_DER",
    );
  }
  const [version, modulus, exponent, privateExponent, p, q, dp, dq, qInv] =
    children
      .slice(0, 9)
      .map((node) => derIntegerBytes(node.value));
  if (!version || version.length !== 1 || version[0] !== 0) {
    throw new PasskeyError(
      "The RSA private key has an unsupported version.",
      "PIV_KEY_DER",
    );
  }
  if (!modulus || modulus.length !== 256) {
    throw new PasskeyError(
      "Only RSA 2048-bit private keys can be imported.",
      "PIV_KEY_LENGTH",
    );
  }
  const parts = [p, q, dp, dq, qInv].map((part) => leftPad(part!, 128));
  const [pBytes, qBytes, dpBytes, dqBytes, qInvBytes] = parts as [
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
  ];
  const pValue = bigIntFromBytes(pBytes);
  const qValue = bigIntFromBytes(qBytes);
  const dValue = privateExponent ? bigIntFromBytes(privateExponent) : 0n;
  if (
    pValue * qValue !== bigIntFromBytes(modulus) ||
    bigIntFromBytes(dpBytes) !== dValue % (pValue - 1n) ||
    bigIntFromBytes(dqBytes) !== dValue % (qValue - 1n) ||
    (bigIntFromBytes(qInvBytes) * qValue) % pValue !== 1n ||
    !exponent ||
    bigIntFromBytes(exponent) < 3n
  ) {
    throw new PasskeyError(
      "The RSA private key components are inconsistent.",
      "PIV_KEY_INVALID",
    );
  }
  return {
    kind: "rsa",
    p: pBytes,
    q: qBytes,
    dp: dpBytes,
    dq: dqBytes,
    qInv: qInvBytes,
  };
}

function curveFromOid(oid: Uint8Array): "p256" | "p384" {
  const value = bytesToHex(oid);
  if (value === P256_OID) return "p256";
  if (value === P384_OID) return "p384";
  throw new PasskeyError(
    "Only P-256 and P-384 EC private keys are supported.",
    "PIV_KEY_CURVE",
  );
}

function parseEcPrivateKey(
  children: DerValue[],
  curve: "p256" | "p384" | null,
): PivEccPrivateKey {
  if (children[0]?.tag !== 0x02 || children[1]?.tag !== 0x04) {
    throw new PasskeyError(
      "The EC private key is malformed.",
      "PIV_KEY_DER",
    );
  }
  let resolved = curve;
  if (!resolved) {
    const parameters = children.find((node) => node.tag === 0xa0);
    if (parameters) {
      resolved = curveFromOid(readDerValue(parameters.value, 0).value);
    }
  }
  if (!resolved) {
    throw new PasskeyError(
      "The EC private key does not identify a supported curve.",
      "PIV_KEY_CURVE",
    );
  }
  const size = resolved === "p256" ? 32 : 48;
  return {
    kind: "ecc",
    curve: resolved,
    scalar: leftPad(children[1]!.value, size),
  };
}

export function parsePivPrivateKey(pem: string): PivPrivateKey {
  if (
    /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) ||
    /Proc-Type:\s*4,\s*ENCRYPTED/i.test(pem)
  ) {
    throw new PasskeyError(
      "Encrypted private keys are not supported. Decrypt the key first.",
      "PIV_KEY_ENCRYPTED",
    );
  }
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!body) {
    throw new PasskeyError(
      "The file does not contain a PEM private key.",
      "PIV_KEY_PEM",
    );
  }
  const root = readDerValue(base64Decode(body), 0);
  if (root.tag !== 0x30) {
    throw new PasskeyError(
      "The private key is not a DER sequence.",
      "PIV_KEY_DER",
    );
  }
  const children = derChildren(root.value);
  if (
    children.length >= 3 &&
    children[0]!.tag === 0x02 &&
    children[1]!.tag === 0x30 &&
    children[2]!.tag === 0x04
  ) {
    const algorithm = derChildren(children[1]!.value);
    const oid = algorithm[0] ? bytesToHex(algorithm[0].value) : "";
    if (oid === RSA_OID) {
      return parseRsaPrivateKey(
        derChildren(readDerValue(children[2]!.value, 0).value),
      );
    }
    if (oid === EC_OID) {
      const curve = algorithm[1]
        ? curveFromOid(algorithm[1].value)
        : null;
      return parseEcPrivateKey(
        derChildren(readDerValue(children[2]!.value, 0).value),
        curve,
      );
    }
    throw new PasskeyError(
      "The private key algorithm is not supported.",
      "PIV_KEY_ALGORITHM",
    );
  }
  if (children[0]?.tag === 0x02 && children[1]?.tag === 0x04) {
    return parseEcPrivateKey(children, null);
  }
  return parseRsaPrivateKey(children);
}

export async function importPivPrivateKey(
  send: SendApdu,
  slot: PivSlot,
  key: PivPrivateKey,
  managementKey: Uint8Array,
): Promise<void> {
  await selectPiv(send);
  await authenticateSelected(send, managementKey);
  if (key.kind === "rsa") {
    const data = concatBytes(
      encodeTlv(0x01, key.p),
      encodeTlv(0x02, key.q),
      encodeTlv(0x03, key.dp),
      encodeTlv(0x04, key.dq),
      encodeTlv(0x05, key.qInv),
    );
    assertSuccess(
      await send(
        extendedApdu(
          0xfe,
          PIV_ALGORITHMS.rsa2048.code,
          Number.parseInt(slot, 16),
          data,
        ),
      ),
    );
    return;
  }
  const body = concatBytes([0x06, key.scalar.length], key.scalar);
  assertSuccess(
    await send(
      buildApdu(
        0xfe,
        PIV_ALGORITHMS[key.curve].code,
        Number.parseInt(slot, 16),
        body,
      ),
    ),
  );
}
