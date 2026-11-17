import { describe, expect, it } from "vitest";
import { bytesToHex, utf8Encode, type SendApdu } from "../../utils/passkey/apdu";
import { decodeBase32 } from "../../utils/passkey/base32";
import { addOathCredential } from "../../utils/passkey/oath";
import { credentialName, parseOtpauthUri } from "../../utils/passkey/otpauth";
import { encodeTlv } from "../../utils/passkey/tlv";

describe("otpauth URI parsing", () => {
  it("parses a sample TOTP URI", () => {
    const parsed = parseOtpauthUri(
      "otpauth://totp/Example:user%40example.test?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Example",
    );
    expect(parsed).toMatchObject({
      type: "totp",
      issuer: "Example",
      account: "user@example.test",
      secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });
    expect(credentialName(parsed.issuer, parsed.account)).toBe(
      "Example:user@example.test",
    );
  });

  it("accepts explicit algorithm, digits, and HOTP counters", () => {
    const parsed = parseOtpauthUri(
      "otpauth://hotp/Example:user?secret=JBSWY3DP&algorithm=SHA256&digits=8&counter=42",
    );
    expect(parsed).toMatchObject({
      type: "hotp",
      issuer: "Example",
      account: "user",
      algorithm: "sha256",
      digits: 8,
      counter: 42,
    });
  });

  it("uses the label issuer when no issuer parameter is present", () => {
    const parsed = parseOtpauthUri(
      "otpauth://totp/Example%20Inc:alice?secret=JBSWY3DP",
    );
    expect(parsed.issuer).toBe("Example Inc");
    expect(parsed.account).toBe("alice");
  });

  it("rejects URIs the device cannot represent", () => {
    expect(() =>
      parseOtpauthUri(
        "otpauth://totp/a?secret=JBSWY3DP&period=60",
      ),
    ).toThrow(/30-second/);
    expect(() =>
      parseOtpauthUri(
        "otpauth://totp/a?secret=JBSWY3DP&algorithm=SHA512",
      ),
    ).toThrow(/SHA1 and SHA256/);
    expect(() =>
      parseOtpauthUri("otpauth://totp/a?secret=JBSWY3DP&digits=9"),
    ).toThrow(/5 to 8 digits/);
    expect(() => parseOtpauthUri("otpauth://totp/a")).toThrow(/secret/);
    expect(() => parseOtpauthUri("https://example.test/")).toThrow(
      /otpauth:\/\//,
    );
  });

  it("saves a parsed sample URI as an OATH credential", async () => {
    const parsed = parseOtpauthUri(
      "otpauth://totp/Example:user%40example.test?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Example",
    );
    const commands: string[] = [];
    const send: SendApdu = async (capdu) => {
      commands.push(capdu);
      return "9000";
    };

    await addOathCredential(send, "", {
      name: credentialName(parsed.issuer, parsed.account),
      key: decodeBase32(parsed.secret),
      type: parsed.type,
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      counter: parsed.counter,
      requireTouch: false,
    });

    const put = commands.at(-1)!;
    const expectedName = bytesToHex(
      encodeTlv(0x71, utf8Encode("Example:user@example.test")),
    );
    expect(put.startsWith("00010000")).toBe(true);
    expect(put).toContain(expectedName);
    expect(put).toContain(`73162106${"00".repeat(20)}`);
  });
});
