import { describe, expect, it } from "vitest";
import {
  buildApdu,
  bytesToHex,
  describeStatus,
  hexToBytes,
  pinErrorMessage,
} from "../../utils/passkey/apdu";

describe("APDU helpers", () => {
  it("round-trips hexadecimal data", () => {
    expect(bytesToHex(hexToBytes("00 A1 b2"))).toBe("00A1B2");
  });

  it("builds a command with data and Le", () => {
    expect(buildApdu(0x20, 0x00, 0x00, hexToBytes("313233"), "00")).toBe(
      "002000000331323300",
    );
  });

  it("formats status words and PIN errors", () => {
    expect(describeStatus("9000")).toBe("Success.");
    expect(describeStatus("63C2")).toContain("2 attempts");
    expect(pinErrorMessage("6700")).toContain("length");
  });
});
