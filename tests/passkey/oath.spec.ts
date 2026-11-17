import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  concatBytes,
  utf8Encode,
  type SendApdu,
} from "../../utils/passkey/apdu";
import {
  addOathCredential,
  parseOathCode,
  parseOathEntries,
  selectOath,
  setOathPassword,
} from "../../utils/passkey/oath";
import { encodeTlv } from "../../utils/passkey/tlv";

describe("OATH parsing", () => {
  it("parses names, TOTP codes, HOTP entries, and touch flags", () => {
    const data = concatBytes(
      encodeTlv(0x71, utf8Encode("sample")),
      encodeTlv(0x76, new Uint8Array([6, 0, 1, 2, 3])),
      encodeTlv(0x71, utf8Encode("hotp")),
      encodeTlv(0x77, new Uint8Array()),
      encodeTlv(0x7c, new Uint8Array()),
    );
    const entries = parseOathEntries(data);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ name: "sample", type: "totp", code: "066051" });
    expect(entries[1]).toMatchObject({ name: "hotp", type: "hotp", requireTouch: true });
  });

  it("parses code digits", () => {
    expect(parseOathCode(new Uint8Array([6, 0, 0, 0, 42]))).toBe("000042");
    expect(() => parseOathCode(new Uint8Array([9, 0, 0, 0, 1]))).toThrow(
      "unsupported code length",
    );
  });

  it("detects a password-protected v1 application", async () => {
    const fci = concatBytes(
      encodeTlv(0x79, new Uint8Array([5, 5, 5])),
      encodeTlv(0x71, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
      encodeTlv(0x74, new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9])),
    );
    const send: SendApdu = async () => `${bytesToHex(fci)}9000`;
    const state = await selectOath(send);
    expect(state.protocol).toBe("v1");
    expect(state.requiresPassword).toBe(true);
  });
  it("accepts a variant application version", async () => {
    const fci = concatBytes(
      encodeTlv(0x79, new Uint8Array([5, 5, 6])),
      encodeTlv(0x71, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
    );
    const send: SendApdu = async () => `${bytesToHex(fci)}9000`;
    const state = await selectOath(send);
    expect(state.protocol).toBe("v1");
    expect(state.requiresPassword).toBe(false);
  });
});

describe("OATH encoding", () => {
  it("writes a four-byte counter and a length-prefixed touch property on legacy applets", async () => {
    const commands: string[] = [];
    const send: SendApdu = async (capdu) => {
      commands.push(capdu);
      return "9000";
    };
    await addOathCredential(send, "", {
      name: "sample",
      key: new Uint8Array([1, 2, 3]),
      type: "hotp",
      algorithm: "sha1",
      digits: 6,
      counter: 1,
      requireTouch: true,
    });
    const put = commands[1]!;
    expect(put.startsWith("00010000")).toBe(true);
    expect(put).toContain("710673616D706C65");
    expect(put).toContain("73051106010203");
    expect(put).toContain("780102");
    expect(put).toContain("7A0400000001");
  });

  it("writes the touch property without a length byte on v1 applets", async () => {
    const fci = concatBytes(
      encodeTlv(0x79, new Uint8Array([5, 5, 5])),
      encodeTlv(0x71, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
    );
    const commands: string[] = [];
    const send: SendApdu = async (capdu) => {
      commands.push(capdu);
      return capdu.startsWith("00A404") ? `${bytesToHex(fci)}9000` : "9000";
    };
    await addOathCredential(send, "", {
      name: "sample",
      key: new Uint8Array([1, 2, 3]),
      type: "totp",
      algorithm: "sha1",
      digits: 6,
      counter: 0,
      requireTouch: true,
    });
    const put = commands[1]!;
    expect(put).toContain("73052106010203");
    expect(put.endsWith("7802")).toBe(true);
    expect(put).not.toContain("780102");
  });

  it("encodes a new OATH password with a derived key and MAC", async () => {
    const fci = concatBytes(
      encodeTlv(0x79, new Uint8Array([5, 5, 5])),
      encodeTlv(0x71, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
      encodeTlv(0x74, new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9])),
    );
    const commands: string[] = [];
    const send: SendApdu = async (capdu) => {
      commands.push(capdu);
      return capdu.startsWith("00A404") ? `${bytesToHex(fci)}9000` : "9000";
    };
    await setOathPassword(send, "123456");
    const command = commands[1]!;
    expect(command.startsWith("00030000")).toBe(true);
    expect(command).toContain("731101");
    expect(command).toContain("740400000000");
    expect(command).toContain("7514");
  });
});
