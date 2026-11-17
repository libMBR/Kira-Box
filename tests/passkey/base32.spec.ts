import { describe, expect, it } from "vitest";
import { decodeBase32 } from "../../utils/passkey/base32";

describe("Base32", () => {
  it("decodes padded and grouped secrets", () => {
    expect([...decodeBase32("MZXW 6===")]).toEqual([102, 111, 111]);
    expect([...decodeBase32("JBSWY3DP")]).toEqual([72, 101, 108, 108, 111]);
  });

  it("rejects invalid input", () => {
    expect(() => decodeBase32("NOT*BASE32")).toThrow("Base32");
    expect(() => decodeBase32("")).toThrow("empty");
  });
});
