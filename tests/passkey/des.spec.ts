import { createCipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "../../utils/passkey/apdu";
import { tripleDesEncryptBlock } from "../../utils/passkey/des";

function referenceTripleDes(
  algorithm: string,
  key: Uint8Array,
  block: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv(algorithm, key, null);
  cipher.setAutoPadding(false);
  return new Uint8Array([...cipher.update(block), ...cipher.final()]);
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

describe("PIV 3DES", () => {
  it("matches OpenSSL for three-key 3DES", () => {
    const key = randomBytes(24);
    const block = randomBytes(8);
    expect(bytesToHex(tripleDesEncryptBlock(block, key))).toBe(
      bytesToHex(referenceTripleDes("des-ede3-ecb", key, block)),
    );
  });

  it("matches OpenSSL for two-key 3DES", () => {
    const key = randomBytes(16);
    const block = randomBytes(8);
    expect(bytesToHex(tripleDesEncryptBlock(block, key))).toBe(
      bytesToHex(referenceTripleDes("des-ede-ecb", key, block)),
    );
  });

  it("rejects invalid block and key lengths", () => {
    expect(() =>
      tripleDesEncryptBlock(new Uint8Array(7), randomBytes(16)),
    ).toThrow(/8-byte blocks/);
    expect(() => tripleDesEncryptBlock(randomBytes(8), randomBytes(12))).toThrow(
      /16 or 24 bytes/,
    );
  });
});
