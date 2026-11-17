import { PasskeyError, utf8Encode } from "./apdu";

export interface OathKey {
  key: CryptoKey;
  bytes: Uint8Array;
}

function subtle(): SubtleCrypto {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new PasskeyError(
      "This browser does not expose the Web Crypto API in a secure context.",
      "NO_WEBCRYPTO",
    );
  }
  return crypto.subtle;
}

export async function deriveOathKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<OathKey> {
  const baseKey = await subtle().importKey(
    "raw",
    utf8Encode(passphrase) as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = new Uint8Array(
    await subtle().deriveBits(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: 1000,
        hash: "SHA-1",
      },
      baseKey,
      128,
    ),
  );
  const key = await subtle().importKey(
    "raw",
    bits as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  return { key, bytes: bits };
}

export async function hmacSha1(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(await subtle().sign("HMAC", key, data as BufferSource));
}
