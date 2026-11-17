import { describe, expect, it } from "vitest";
import { PasskeyError, utf8Encode } from "../../utils/passkey/apdu";
import { encodeTlv, findTlv, parseTlv } from "../../utils/passkey/tlv";

describe("TLV parser", () => {
  it("parses nested values", () => {
    const nested = encodeTlv(0xc5, utf8Encode("abc"));
    const outer = encodeTlv(0x73, nested);
    const parsed = parseTlv(outer);
    expect(parsed[0]!.tag).toBe(0x73);
    expect(parseTlv(parsed[0]!.value)[0]!.tag).toBe(0xc5);
  });

  it("parses long two-byte lengths", () => {
    const value = new Uint8Array(200).fill(0x5a);
    const parsed = parseTlv(encodeTlv(0x70, value));
    expect(parsed[0]!.value.length).toBe(200);
    expect(findTlv(parsed, 0x70)?.value[199]).toBe(0x5a);
  });

  it("rejects truncated values", () => {
    expect(() => parseTlv(new Uint8Array([0x71, 0x05, 0x00]))).toThrow(PasskeyError);
  });
});
