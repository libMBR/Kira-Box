import {
  assertSuccess,
  buildApdu,
  byteHex,
  bytesToHex,
  concatBytes,
  hexToBytes,
  PasskeyError,
  pinErrorMessage,
  responseData,
  utf8Decode,
  utf8Encode,
  type SendApdu,
} from "./apdu";
import { encodeTlv, findTlv, nestedTlv, parseTlv, type Tlv } from "./tlv";

export const OPENPGP_AID = "D27600012401";

export type OpenPgpKey = "signature" | "encryption" | "authentication";
export type TouchPolicy = "off" | "on" | "permanent" | "unavailable";
export type OpenPgpKeyStatus = "missing" | "generated" | "imported" | "unknown";
export type OpenPgpAlgorithm =
  | "rsa2048"
  | "rsa4096"
  | "p256"
  | "p384"
  | "secp256k1"
  | "curve25519";

export interface OpenPgpSlotState {
  algorithm: OpenPgpAlgorithm | null;
  key: OpenPgpKeyStatus;
  certificate: boolean;
}

export interface OpenPgpCard {
  version: string;
  manufacturerId: string;
  serialNumber: string;
  cardholder: string;
  publicKeyUrl: string;
  fingerprints: Record<OpenPgpKey, string>;
  policies: Record<OpenPgpKey, TouchPolicy>;
  cacheTime: number | null;
  slots: Record<OpenPgpKey, OpenPgpSlotState>;
}

export interface OpenPgpKeyOperationResult {
  fingerprint: string;
  metadataStored: boolean;
}

export interface OpenPgpPrivateKeyInput {
  pem?: string;
  hex?: string;
}

interface SlotDefinition {
  algorithmTag: number;
  keyReference: string;
  fingerprintTag: number;
  dateTag: number;
  certificateOccurrence: number;
}

const KEY_ORDER: OpenPgpKey[] = ["signature", "encryption", "authentication"];

const SLOTS: Record<OpenPgpKey, SlotDefinition> = {
  signature: {
    algorithmTag: 0xc1,
    keyReference: "B6",
    fingerprintTag: 0xc7,
    dateTag: 0xce,
    certificateOccurrence: 2,
  },
  encryption: {
    algorithmTag: 0xc2,
    keyReference: "B8",
    fingerprintTag: 0xc8,
    dateTag: 0xcf,
    certificateOccurrence: 1,
  },
  authentication: {
    algorithmTag: 0xc3,
    keyReference: "A4",
    fingerprintTag: 0xc9,
    dateTag: 0xd0,
    certificateOccurrence: 0,
  },
};

const CERTIFICATE_SELECT_DATA = new Uint8Array([0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21]);
const MAX_CERTIFICATE_LENGTH = 1152;

const ALGORITHM_LABELS: Record<OpenPgpAlgorithm, string> = {
  rsa2048: "RSA-2048",
  rsa4096: "RSA-4096",
  p256: "NIST P-256",
  p384: "NIST P-384",
  secp256k1: "secp256k1",
  curve25519: "Curve25519",
};

export const OPENPGP_GENERATION_ALGORITHMS: OpenPgpAlgorithm[] = [
  "rsa2048",
  "p256",
  "p384",
  "secp256k1",
  "curve25519",
];

export const OPENPGP_IMPORT_ALGORITHMS: OpenPgpAlgorithm[] = [
  "rsa2048",
  "rsa4096",
  "p256",
  "p384",
  "secp256k1",
  "curve25519",
];

const UIF_TAGS: Record<OpenPgpKey, number> = {
  signature: 0xd6,
  encryption: 0xd7,
  authentication: 0xd8,
};

const UIF_TAG_HEX: Record<OpenPgpKey, string> = {
  signature: "D6",
  encryption: "D7",
  authentication: "D8",
};

const POLICY_VALUES: Record<Exclude<TouchPolicy, "unavailable">, number> = {
  off: 0,
  on: 1,
  permanent: 2,
};

export function algorithmLabel(value: OpenPgpAlgorithm | null): string {
  return value === null ? "Not set" : ALGORITHM_LABELS[value];
}

export async function selectOpenPgp(send: SendApdu): Promise<void> {
  assertSuccess(await send(`00A4040006${OPENPGP_AID}`));
}

async function getData(send: SendApdu, p1: string, p2: string): Promise<Uint8Array> {
  const response = await send(`00CA${p1}${p2}00`);
  assertSuccess(response);
  return responseData(response);
}

function policyFromByte(value: number | undefined): TouchPolicy {
  if (value === 0) return "off";
  if (value === 1) return "on";
  if (value === 2) return "permanent";
  return "unavailable";
}

export function formatFingerprint(value: Uint8Array): string {
  if (!value.some((byte) => byte !== 0)) {
    return "Not set";
  }
  return (
    bytesToHex(value)
      .match(/.{1,4}/g)
      ?.join(" ") ?? ""
  );
}

function decodeAlgorithmAttributes(value: Uint8Array | undefined): OpenPgpAlgorithm | null {
  if (!value || value.length < 2) return null;
  const algorithmId = value[0]!;
  if (algorithmId === 0x01) {
    const bits = ((value[1] ?? 0) << 8) | (value[2] ?? 0);
    if (bits === 2048) return "rsa2048";
    if (bits === 4096) return "rsa4096";
    return null;
  }
  if (algorithmId !== 0x12 && algorithmId !== 0x13 && algorithmId !== 0x16) {
    return null;
  }
  const oid = bytesToHex(value.subarray(1));
  if (oid.startsWith("2A8648CE3D030107")) return "p256";
  if (oid.startsWith("2B81040022")) return "p384";
  if (oid.startsWith("2B8104000A")) return "secp256k1";
  if (oid.startsWith("2B06010401DA470F01")) return "curve25519";
  if (oid.startsWith("2B060104019755010501")) return "curve25519";
  return null;
}

function algorithmAttributes(
  algorithm: OpenPgpAlgorithm,
  slot: OpenPgpKey,
): Uint8Array {
  const decryption = slot === "encryption";
  switch (algorithm) {
    case "rsa2048":
      return hexToBytes("010800002000");
    case "rsa4096":
      return hexToBytes("011000002000");
    case "p256":
      return hexToBytes(`${decryption ? "12" : "13"}2A8648CE3D030107`);
    case "p384":
      return hexToBytes(`${decryption ? "12" : "13"}2B81040022`);
    case "secp256k1":
      return hexToBytes(`${decryption ? "12" : "13"}2B8104000A`);
    case "curve25519":
      return decryption
        ? hexToBytes("122B060104019755010501")
        : hexToBytes("162B06010401DA470F01");
    default:
      throw new PasskeyError("Unsupported key algorithm.", "UNSUPPORTED_ALGORITHM");
  }
}

function buildExtendedApdu(
  ins: number,
  p1: number,
  p2: number,
  data: Uint8Array,
): string {
  if (data.length > 0xffff) {
    throw new PasskeyError("APDU data is too long for the device.", "APDU_TOO_LONG");
  }
  const header = `00${byteHex(ins)}${byteHex(p1)}${byteHex(p2)}`;
  const length = data.length.toString(16).padStart(4, "0").toUpperCase();
  return `${header}00${length}${bytesToHex(data)}`;
}

function isMissingError(error: unknown): boolean {
  return (
    error instanceof PasskeyError &&
    error.code !== undefined &&
    ["6A82", "6A83", "6A86", "6A88"].includes(error.code)
  );
}

async function selectCertificateOccurrence(
  send: SendApdu,
  slot: OpenPgpKey,
): Promise<void> {
  assertSuccess(
    await send(
      buildApdu(
        0xa5,
        SLOTS[slot].certificateOccurrence,
        0x04,
        CERTIFICATE_SELECT_DATA,
        "00",
      ),
    ),
  );
}

async function readPublicKeyData(send: SendApdu, slot: OpenPgpKey): Promise<Uint8Array> {
  const response = await send(
    `00478100000002${SLOTS[slot].keyReference}000000`,
  );
  assertSuccess(response);
  return responseData(response);
}

async function readKeyInformation(
  send: SendApdu,
): Promise<Record<OpenPgpKey, OpenPgpKeyStatus>> {
  const statuses: Record<OpenPgpKey, OpenPgpKeyStatus> = {
    signature: "unknown",
    encryption: "unknown",
    authentication: "unknown",
  };
  let information: Uint8Array;
  try {
    information = await getData(send, "00", "DE");
  } catch {
    information = new Uint8Array();
  }
  if (information.length >= 8 && information[0] === 0xde) {
    const length = information[1]!;
    if (information.length === length + 2) {
      information = information.subarray(2);
    }
  }
  if (information.length >= 6) {
    KEY_ORDER.forEach((key, index) => {
      const status = information[index * 2 + 1];
      statuses[key] =
        status === 0
          ? "missing"
          : status === 1
            ? "generated"
            : status === 2
              ? "imported"
              : "unknown";
    });
    return statuses;
  }
  for (const key of KEY_ORDER) {
    try {
      const publicKey = await readPublicKeyData(send, key);
      statuses[key] = publicKey.length > 0 ? "unknown" : "missing";
    } catch {
      statuses[key] = "missing";
    }
  }
  return statuses;
}

export async function readOpenPgpCard(send: SendApdu): Promise<OpenPgpCard> {
  await selectOpenPgp(send);
  const applicationData = await getData(send, "00", "6E");
  const tlv = parseTlv(applicationData);
  const aid = findTlv(tlv, 0x4f)?.value;
  if (!aid || aid.length < 14) {
    throw new PasskeyError(
      "The device returned an invalid OpenPGP application identifier.",
      "OPENPGP_AID",
    );
  }
  const discretionary = nestedTlv(tlv, 0x73) ?? [];
  const fingerprintData = findTlv(discretionary, 0xc5)?.value;
  const fingerprints: Record<OpenPgpKey, string> = {
    signature:
      fingerprintData && fingerprintData.length >= 20
        ? formatFingerprint(fingerprintData.slice(0, 20))
        : "Not set",
    encryption:
      fingerprintData && fingerprintData.length >= 40
        ? formatFingerprint(fingerprintData.slice(20, 40))
        : "Not set",
    authentication:
      fingerprintData && fingerprintData.length >= 60
        ? formatFingerprint(fingerprintData.slice(40, 60))
        : "Not set",
  };
  const policies: Record<OpenPgpKey, TouchPolicy> = {
    signature: "unavailable",
    encryption: "unavailable",
    authentication: "unavailable",
  };
  for (const key of Object.keys(UIF_TAGS) as OpenPgpKey[]) {
    const value = findTlv(discretionary, UIF_TAGS[key])?.value;
    policies[key] =
      value && value.length > 0 ? policyFromByte(value[0]) : "unavailable";
  }

  let cardholder = "";
  const cardholderData = parseTlv(await getData(send, "00", "65"));
  const name = findTlv(cardholderData, 0x5b)?.value;
  if (name) cardholder = utf8Decode(name);

  const publicKeyUrl = utf8Decode(await getData(send, "5F", "50"));

  let cacheTime: number | null;
  try {
    const cacheData = await getData(send, "01", "02");
    cacheTime = cacheData.length > 0 ? (cacheData[0] ?? null) : null;
  } catch {
    cacheTime = null;
  }

  const keyStatuses = await readKeyInformation(send);
  const slots: Record<OpenPgpKey, OpenPgpSlotState> = {
    signature: {
      algorithm: decodeAlgorithmAttributes(findTlv(discretionary, 0xc1)?.value),
      key: keyStatuses.signature,
      certificate: false,
    },
    encryption: {
      algorithm: decodeAlgorithmAttributes(findTlv(discretionary, 0xc2)?.value),
      key: keyStatuses.encryption,
      certificate: false,
    },
    authentication: {
      algorithm: decodeAlgorithmAttributes(findTlv(discretionary, 0xc3)?.value),
      key: keyStatuses.authentication,
      certificate: false,
    },
  };
  for (const key of KEY_ORDER) {
    try {
      slots[key].certificate = (await readOpenPgpCertificate(send, key)) !== null;
    } catch {
      slots[key].certificate = false;
    }
  }

  return {
    version: `${aid[6]}.${aid[7]}`,
    manufacturerId: bytesToHex(aid.slice(8, 10)),
    serialNumber: bytesToHex(aid.slice(10, 14)),
    cardholder,
    publicKeyUrl,
    fingerprints,
    policies,
    cacheTime,
    slots,
  };
}

export async function changeOpenPgpPin(
  send: SendApdu,
  key: "user" | "admin",
  oldPin: string,
  newPin: string,
): Promise<void> {
  const minimum = key === "admin" ? 8 : 6;
  if (newPin.length < minimum || newPin.length > 64) {
    throw new PasskeyError(
      `The new PIN must be ${minimum} to 64 characters.`,
      "INVALID_PIN",
    );
  }
  await selectOpenPgp(send);
  const response = await send(
    buildApdu(
      0x24,
      0x00,
      key === "admin" ? 0x83 : 0x81,
      new Uint8Array([...utf8Encode(oldPin), ...utf8Encode(newPin)]),
    ),
  );
  assertSuccess(response);
}

export async function verifyOpenPgpAdminPin(
  send: SendApdu,
  pin: string,
): Promise<void> {
  const response = await send(buildApdu(0x20, 0x00, 0x83, utf8Encode(pin)));
  if (response.slice(-4) !== "9000") {
    throw new PasskeyError(pinErrorMessage(response.slice(-4)), response.slice(-4));
  }
}

export async function setOpenPgpUif(
  send: SendApdu,
  key: OpenPgpKey,
  policy: Exclude<TouchPolicy, "unavailable">,
  adminPin: string,
): Promise<void> {
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  const data = new Uint8Array([POLICY_VALUES[policy], 0x20]);
  assertSuccess(
    await send(buildApdu(0xda, 0x00, Number.parseInt(UIF_TAG_HEX[key], 16), data)),
  );
}

export async function setOpenPgpCacheTime(
  send: SendApdu,
  seconds: number,
  adminPin: string,
): Promise<void> {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 255) {
    throw new PasskeyError(
      "Cache time must be between 0 and 255 seconds.",
      "INVALID_VALUE",
    );
  }
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  assertSuccess(
    await send(buildApdu(0xda, 0x01, 0x02, new Uint8Array([seconds]))),
  );
}

export async function setOpenPgpUrl(
  send: SendApdu,
  url: string,
  adminPin: string,
): Promise<void> {
  requireAdminPin(adminPin);
  const encoded = utf8Encode(url);
  if (encoded.length > 255) {
    throw new PasskeyError(
      "The public key URL cannot exceed 255 bytes.",
      "INVALID_VALUE",
    );
  }
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  assertSuccess(await send(buildApdu(0xda, 0x5f, 0x50, encoded)));
}

export async function readOpenPgpCertificate(
  send: SendApdu,
  slot: OpenPgpKey,
): Promise<Uint8Array | null> {
  await selectOpenPgp(send);
  try {
    await selectCertificateOccurrence(send, slot);
  } catch (error) {
    if (isMissingError(error)) return null;
    throw error;
  }
  try {
    const data = await getData(send, "7F", "21");
    if (data.length === 0) return null;
    if (data[0] === 0x7f && data[1] === 0x21) {
      try {
        const parsed = parseTlv(data);
        const value = findTlv(parsed, 0x7f21)?.value;
        return value && value.length > 0 ? value : null;
      } catch {
        return data;
      }
    }
    return data;
  } catch (error) {
    if (isMissingError(error)) return null;
    throw error;
  }
}

export async function writeOpenPgpCertificate(
  send: SendApdu,
  slot: OpenPgpKey,
  certificate: Uint8Array,
  adminPin: string,
): Promise<void> {
  requireAdminPin(adminPin);
  if (certificate.length === 0) {
    throw new PasskeyError(
      "The selected certificate file is empty.",
      "INVALID_CERTIFICATE",
    );
  }
  if (certificate.length > MAX_CERTIFICATE_LENGTH) {
    throw new PasskeyError(
      `The certificate is larger than the ${MAX_CERTIFICATE_LENGTH}-byte card limit.`,
      "CERTIFICATE_TOO_LARGE",
    );
  }
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  await selectCertificateOccurrence(send, slot);
  assertSuccess(await send(buildExtendedApdu(0xda, 0x7f, 0x21, certificate)));
}

export async function deleteOpenPgpCertificate(
  send: SendApdu,
  slot: OpenPgpKey,
  adminPin: string,
): Promise<void> {
  requireAdminPin(adminPin);
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  await selectCertificateOccurrence(send, slot);
  assertSuccess(await send("00DA7F21"));
}

export async function generateOpenPgpKey(
  send: SendApdu,
  slot: OpenPgpKey,
  algorithm: OpenPgpAlgorithm,
  adminPin: string,
): Promise<OpenPgpKeyOperationResult> {
  requireAdminPin(adminPin);
  if (algorithm === "rsa4096") {
    throw new PasskeyError(
      "On-card RSA-4096 generation is not supported. Import an RSA-4096 key instead.",
      "UNSUPPORTED_ALGORITHM",
    );
  }
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  assertSuccess(
    await send(
      buildApdu(0xda, 0x00, SLOTS[slot].algorithmTag, algorithmAttributes(algorithm, slot)),
    ),
  );
  assertSuccess(await send(`00478000000002${SLOTS[slot].keyReference}000000`));
  return finishKeyWrite(send, slot, algorithm);
}

export async function importOpenPgpPrivateKey(
  send: SendApdu,
  slot: OpenPgpKey,
  algorithm: OpenPgpAlgorithm,
  input: OpenPgpPrivateKeyInput,
  adminPin: string,
): Promise<OpenPgpKeyOperationResult> {
  requireAdminPin(adminPin);
  const material = await buildPrivateKeyMaterial(algorithm, input);
  await selectOpenPgp(send);
  await verifyOpenPgpAdminPin(send, adminPin);
  assertSuccess(
    await send(
      buildApdu(0xda, 0x00, SLOTS[slot].algorithmTag, algorithmAttributes(algorithm, slot)),
    ),
  );
  assertSuccess(
    await send(
      buildExtendedApdu(0xdb, 0x3f, 0xff, buildImportData(slot, material)),
    ),
  );
  return finishKeyWrite(send, slot, algorithm);
}

function requireAdminPin(pin: string): void {
  if (pin.length === 0) {
    throw new PasskeyError("Enter the Admin PIN first.", "ADMIN_PIN_REQUIRED");
  }
}

async function finishKeyWrite(
  send: SendApdu,
  slot: OpenPgpKey,
  algorithm: OpenPgpAlgorithm,
): Promise<OpenPgpKeyOperationResult> {
  const timestamp = Math.floor(Date.now() / 1000);
  let fingerprint = "";
  let metadataStored: boolean;
  try {
    const publicKey = await readPublicKeyData(send, slot);
    const parts = parsePublicKeyData(algorithm, publicKey);
    const packet = buildPublicKeyPacket(algorithm, slot, timestamp, parts);
    const digest = await computeFingerprint(packet);
    fingerprint = formatFingerprint(digest);
    try {
      assertSuccess(
        await send(buildApdu(0xda, 0x00, SLOTS[slot].dateTag, timestampBytes(timestamp))),
      );
      assertSuccess(
        await send(buildApdu(0xda, 0x00, SLOTS[slot].fingerprintTag, digest)),
      );
      metadataStored = true;
    } catch {
      metadataStored = false;
    }
  } catch {
    metadataStored = false;
  }
  return { fingerprint, metadataStored };
}

interface PublicKeyParts {
  modulus?: Uint8Array;
  exponent?: Uint8Array;
  point?: Uint8Array;
}

interface RsaPrivateKeyMaterial {
  kind: "rsa";
  exponent: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  qi: Uint8Array;
  dp: Uint8Array;
  dq: Uint8Array;
}

interface EcPrivateKeyMaterial {
  kind: "ec";
  scalar: Uint8Array;
}

type PrivateKeyMaterial = RsaPrivateKeyMaterial | EcPrivateKeyMaterial;

function padLeft(value: Uint8Array, length: number, label: string): Uint8Array {
  if (value.length === length) return value;
  if (value.length > length) {
    throw new PasskeyError(
      `The ${label} is longer than the selected key size allows.`,
      "INVALID_KEY",
    );
  }
  const result = new Uint8Array(length);
  result.set(value, length - value.length);
  return result;
}

function timestampBytes(timestamp: number): Uint8Array {
  return new Uint8Array([
    (timestamp >>> 24) & 0xff,
    (timestamp >>> 16) & 0xff,
    (timestamp >>> 8) & 0xff,
    timestamp & 0xff,
  ]);
}

function lengthField(length: number): number[] {
  if (length <= 0x7f) return [length];
  if (length <= 0xff) return [0x81, length];
  if (length <= 0xffff) return [0x82, (length >> 8) & 0xff, length & 0xff];
  throw new PasskeyError("Key component is too long.", "INVALID_KEY");
}

function descriptor(tag: number, length: number): Uint8Array {
  return new Uint8Array([tag, ...lengthField(length)]);
}

function buildImportData(
  slot: OpenPgpKey,
  material: PrivateKeyMaterial,
): Uint8Array {
  const controlReference = hexToBytes(`${SLOTS[slot].keyReference}00`);
  if (material.kind === "rsa") {
    const exponent = padLeft(material.exponent, 4, "public exponent");
    const template = concatBytes(
      descriptor(0x91, exponent.length),
      descriptor(0x92, material.p.length),
      descriptor(0x93, material.q.length),
      descriptor(0x94, material.qi.length),
      descriptor(0x95, material.dp.length),
      descriptor(0x96, material.dq.length),
    );
    const keyData = concatBytes(
      exponent,
      material.p,
      material.q,
      material.qi,
      material.dp,
      material.dq,
    );
    return encodeTlv(
      0x4d,
      concatBytes(
        controlReference,
        encodeTlv(0x7f48, template),
        encodeTlv(0x5f48, keyData),
      ),
    );
  }
  const template = descriptor(0x92, material.scalar.length);
  return encodeTlv(
    0x4d,
    concatBytes(
      controlReference,
      encodeTlv(0x7f48, template),
      encodeTlv(0x5f48, material.scalar),
    ),
  );
}

async function buildPrivateKeyMaterial(
  algorithm: OpenPgpAlgorithm,
  input: OpenPgpPrivateKeyInput,
): Promise<PrivateKeyMaterial> {
  if (algorithm === "rsa2048" || algorithm === "rsa4096") {
    if (!input.pem?.trim()) {
      throw new PasskeyError(
        "Choose an unencrypted PEM private key for RSA import.",
        "INVALID_KEY",
      );
    }
    return importRsaPrivateKey(input.pem, algorithm);
  }
  if (input.hex?.trim()) {
    return { kind: "ec", scalar: parseScalarHex(input.hex, algorithm) };
  }
  if (
    (algorithm === "p256" || algorithm === "p384") &&
    input.pem?.trim()
  ) {
    return { kind: "ec", scalar: await importEcPrivateKey(input.pem, algorithm) };
  }
  throw new PasskeyError(
    algorithm === "secp256k1"
      ? "Enter the 32-byte private scalar as hex. PEM import is not supported for secp256k1."
      : "Enter the 32-byte private key as hex, or choose a PEM key for NIST P-256 and P-384.",
    "INVALID_KEY",
  );
}

function parseScalarHex(value: string, algorithm: OpenPgpAlgorithm): Uint8Array {
  const cleaned = value.replace(/[\s:]/g, "");
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(cleaned);
  } catch {
    throw new PasskeyError(
      "The private key must be hexadecimal data.",
      "INVALID_KEY",
    );
  }
  const expected = algorithm === "p384" ? 48 : 32;
  if (bytes.length !== expected) {
    throw new PasskeyError(
      `The private key must be ${expected} bytes (${expected * 2} hex characters).`,
      "INVALID_KEY",
    );
  }
  if (!bytes.some((byte) => byte !== 0)) {
    throw new PasskeyError("The private key cannot be all zeroes.", "INVALID_KEY");
  }
  return bytes;
}

function decodePem(pem: string): { der: Uint8Array; label: string } {
  const match = pem.match(
    /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/,
  );
  if (!match) {
    throw new PasskeyError(
      "The selected file is not a valid PEM private key.",
      "INVALID_KEY",
    );
  }
  const label = match[1]!.trim();
  if (label === "ENCRYPTED PRIVATE KEY") {
    throw new PasskeyError(
      "Encrypted private keys are not supported. Remove the passphrase first.",
      "INVALID_KEY",
    );
  }
  const body = match[2]!.replace(/[^A-Za-z0-9+/=]/g, "");
  if (body.length === 0) {
    throw new PasskeyError("The PEM file does not contain key data.", "INVALID_KEY");
  }
  try {
    const binary = atob(body);
    const der = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      der[index] = binary.charCodeAt(index);
    }
    return { der, label };
  } catch {
    throw new PasskeyError(
      "The PEM file contains invalid base64 data.",
      "INVALID_KEY",
    );
  }
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function wrapRsaPrivateKey(der: Uint8Array): Uint8Array {
  const algorithmIdentifier = hexToBytes("300D06092A864886F70D0101010500");
  return encodeTlv(
    0x30,
    concatBytes(
      hexToBytes("020100"),
      algorithmIdentifier,
      encodeTlv(0x04, der),
    ),
  );
}

function wrapEcPrivateKey(
  der: Uint8Array,
  algorithm: "p256" | "p384",
): Uint8Array {
  const curveOid =
    algorithm === "p256" ? hexToBytes("2A8648CE3D030107") : hexToBytes("2B81040022");
  const algorithmIdentifier = encodeTlv(
    0x30,
    concatBytes(hexToBytes("06072A8648CE3D0201"), encodeTlv(0x06, curveOid)),
  );
  return encodeTlv(
    0x30,
    concatBytes(
      hexToBytes("020100"),
      algorithmIdentifier,
      encodeTlv(0x04, der),
    ),
  );
}

interface RsaJwk extends JsonWebKey {
  n?: string;
  e?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
}

interface EcJwk extends JsonWebKey {
  d?: string;
}

function webCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new PasskeyError(
      "This browser does not support the Web Crypto API needed to read PEM keys.",
      "CRYPTO_UNAVAILABLE",
    );
  }
  return subtle;
}

async function importRsaPrivateKey(
  pem: string,
  algorithm: "rsa2048" | "rsa4096",
): Promise<RsaPrivateKeyMaterial> {
  const { der, label } = decodePem(pem);
  const pkcs8 = label === "RSA PRIVATE KEY" ? wrapRsaPrivateKey(der) : der;
  let key: CryptoKey;
  try {
    key = await webCrypto().importKey(
      "pkcs8",
      pkcs8.slice(),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["sign"],
    );
  } catch {
    throw new PasskeyError(
      "The PEM file could not be read as an RSA private key. Use an unencrypted RSA key.",
      "INVALID_KEY",
    );
  }
  const jwk = (await webCrypto().exportKey("jwk", key)) as RsaJwk;
  if (!jwk.n || !jwk.e || !jwk.p || !jwk.q || !jwk.dp || !jwk.dq || !jwk.qi) {
    throw new PasskeyError(
      "The RSA private key is missing required components.",
      "INVALID_KEY",
    );
  }
  const modulusLength = algorithm === "rsa2048" ? 256 : 512;
  const half = modulusLength / 2;
  const modulus = base64UrlToBytes(jwk.n);
  if (modulus.length !== modulusLength) {
    throw new PasskeyError(
      `The private key is not ${algorithm === "rsa2048" ? "2048" : "4096"} bits.`,
      "INVALID_KEY",
    );
  }
  return {
    kind: "rsa",
    exponent: base64UrlToBytes(jwk.e),
    p: padLeft(base64UrlToBytes(jwk.p), half, "prime p"),
    q: padLeft(base64UrlToBytes(jwk.q), half, "prime q"),
    qi: padLeft(base64UrlToBytes(jwk.qi), half, "CRT coefficient"),
    dp: padLeft(base64UrlToBytes(jwk.dp), half, "CRT exponent"),
    dq: padLeft(base64UrlToBytes(jwk.dq), half, "CRT exponent"),
  };
}

async function importEcPrivateKey(
  pem: string,
  algorithm: "p256" | "p384",
): Promise<Uint8Array> {
  const { der, label } = decodePem(pem);
  const pkcs8 = label === "EC PRIVATE KEY" ? wrapEcPrivateKey(der, algorithm) : der;
  let key: CryptoKey;
  try {
    key = await webCrypto().importKey(
      "pkcs8",
      pkcs8.slice(),
      {
        name: "ECDSA",
        namedCurve: algorithm === "p256" ? "P-256" : "P-384",
      },
      true,
      ["sign"],
    );
  } catch {
    throw new PasskeyError(
      "The PEM file could not be read with the selected curve. Use an unencrypted EC key.",
      "INVALID_KEY",
    );
  }
  const jwk = (await webCrypto().exportKey("jwk", key)) as EcJwk;
  if (!jwk.d) {
    throw new PasskeyError(
      "The EC private key is missing its private scalar.",
      "INVALID_KEY",
    );
  }
  return padLeft(
    base64UrlToBytes(jwk.d),
    algorithm === "p256" ? 32 : 48,
    "private scalar",
  );
}

function normalizePoint(
  algorithm: OpenPgpAlgorithm,
  raw: Uint8Array,
): Uint8Array {
  if (algorithm === "curve25519") {
    if (raw.length === 33 && (raw[0] === 0x40 || raw[0] === 0x04)) {
      return raw.subarray(1);
    }
    if (raw.length === 32) return raw;
    throw new PasskeyError(
      "The device returned an invalid Curve25519 public key.",
      "INVALID_RESPONSE",
    );
  }
  const coordinateLength =
    algorithm === "p384" ? 48 : algorithm === "p256" || algorithm === "secp256k1" ? 32 : 0;
  if (coordinateLength === 0) {
    throw new PasskeyError("Unsupported key algorithm.", "UNSUPPORTED_ALGORITHM");
  }
  if (raw.length === coordinateLength * 2) {
    return concatBytes(new Uint8Array([0x04]), raw);
  }
  if (raw.length === coordinateLength * 2 + 1 && raw[0] === 0x04) {
    return raw;
  }
  throw new PasskeyError(
    "The device returned an invalid elliptic-curve public key.",
    "INVALID_RESPONSE",
  );
}

function parsePublicKeyData(
  algorithm: OpenPgpAlgorithm,
  data: Uint8Array,
): PublicKeyParts {
  let parsed: Tlv[];
  try {
    parsed = parseTlv(data);
  } catch {
    throw new PasskeyError(
      "The device returned invalid public key data.",
      "INVALID_RESPONSE",
    );
  }
  const root = findTlv(parsed, 0x7f49);
  const inner = root ? parseTlv(root.value) : parsed;
  if (algorithm === "rsa2048" || algorithm === "rsa4096") {
    const modulus = findTlv(inner, 0x81)?.value;
    const exponent = findTlv(inner, 0x82)?.value;
    if (!modulus || !exponent) {
      throw new PasskeyError(
        "The device returned an incomplete RSA public key.",
        "INVALID_RESPONSE",
      );
    }
    return { modulus, exponent };
  }
  const point = findTlv(inner, 0x86)?.value;
  if (!point) {
    throw new PasskeyError(
      "The device returned an incomplete public key.",
      "INVALID_RESPONSE",
    );
  }
  return { point: normalizePoint(algorithm, point) };
}

function mpi(bytes: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < bytes.length - 1 && bytes[offset] === 0) offset++;
  const value = bytes.subarray(offset);
  if (value.length === 0 || !value.some((byte) => byte !== 0)) {
    return new Uint8Array([0, 0]);
  }
  const first = value[0]!;
  const bits = (value.length - 1) * 8 + (32 - Math.clz32(first));
  return concatBytes(
    new Uint8Array([(bits >> 8) & 0xff, bits & 0xff]),
    value,
  );
}

function curveOid(algorithm: OpenPgpAlgorithm): Uint8Array {
  switch (algorithm) {
    case "p256":
      return hexToBytes("2A8648CE3D030107");
    case "p384":
      return hexToBytes("2B81040022");
    case "secp256k1":
      return hexToBytes("2B8104000A");
    case "curve25519":
      return hexToBytes("2B06010401DA470F01");
    default:
      throw new PasskeyError("Unsupported key algorithm.", "UNSUPPORTED_ALGORITHM");
  }
}

function buildPublicKeyPacket(
  algorithm: OpenPgpAlgorithm,
  slot: OpenPgpKey,
  timestamp: number,
  parts: PublicKeyParts,
): Uint8Array {
  const time = timestampBytes(timestamp);
  if (algorithm === "rsa2048" || algorithm === "rsa4096") {
    if (!parts.modulus || !parts.exponent) {
      throw new PasskeyError("The RSA public key is incomplete.", "INVALID_RESPONSE");
    }
    return concatBytes(
      new Uint8Array([0x04]),
      time,
      new Uint8Array([0x01]),
      mpi(parts.modulus),
      mpi(parts.exponent),
    );
  }
  if (!parts.point) {
    throw new PasskeyError("The public key is incomplete.", "INVALID_RESPONSE");
  }
  const decryption = slot === "encryption";
  const oid =
    algorithm === "curve25519"
      ? decryption
        ? hexToBytes("2B060104019755010501")
        : hexToBytes("2B06010401DA470F01")
      : curveOid(algorithm);
  const encodedPoint =
    algorithm === "curve25519"
      ? concatBytes(new Uint8Array([0x40]), parts.point)
      : parts.point;
  const algorithmId = decryption ? 0x12 : algorithm === "curve25519" ? 0x16 : 0x13;
  const prefix = concatBytes(
    new Uint8Array([0x04]),
    time,
    new Uint8Array([algorithmId, oid.length]),
    oid,
    mpi(encodedPoint),
  );
  return decryption
    ? concatBytes(prefix, new Uint8Array([0x03, 0x01, 0x08, 0x07]))
    : prefix;
}

async function computeFingerprint(packet: Uint8Array): Promise<Uint8Array> {
  const body = concatBytes(
    new Uint8Array([
      0x99,
      (packet.length >> 8) & 0xff,
      packet.length & 0xff,
    ]),
    packet,
  );
  const digest = await webCrypto().digest("SHA-1", body.slice());
  return new Uint8Array(digest);
}
