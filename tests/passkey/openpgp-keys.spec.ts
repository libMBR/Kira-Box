import { describe, expect, it } from "vitest";
import type { SendApdu } from "../../utils/passkey/apdu";
import { importOpenPgpPrivateKey } from "../../utils/passkey/openpgp";

function pemFromDer(der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `-----BEGIN PRIVATE KEY-----\n${btoa(binary)}\n-----END PRIVATE KEY-----`;
}

function capture(): { send: SendApdu; commands: string[] } {
  const commands: string[] = [];
  return {
    commands,
    send: async (capdu: string) => {
      commands.push(capdu);
      return "9000";
    },
  };
}

describe("OpenPGP private key import", () => {
  it("converts a PKCS#8 RSA key into a card import APDU", async () => {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const pem = pemFromDer(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey),
    );
    const { send, commands } = capture();
    await importOpenPgpPrivateKey(
      send,
      "signature",
      "rsa2048",
      { pem },
      "12345678",
    );
    const importApdu = commands.find((capdu) => capdu.startsWith("00DB3FFF"));
    expect(importApdu).toBeDefined();
    expect(importApdu).toContain("4D");
    expect(importApdu).toContain("7F48");
    expect(importApdu).toContain("5F48");
  });

  it("converts a PKCS#8 P-256 key into a card import APDU", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const pem = pemFromDer(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey),
    );
    const { send, commands } = capture();
    await importOpenPgpPrivateKey(
      send,
      "signature",
      "p256",
      { pem },
      "12345678",
    );
    const importApdu = commands.find((capdu) => capdu.startsWith("00DB3FFF"));
    expect(importApdu).toBeDefined();
    expect(importApdu).toContain("5F4820");
  });
});
