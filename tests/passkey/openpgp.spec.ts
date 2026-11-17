import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8Encode,
  type SendApdu,
} from "../../utils/passkey/apdu";
import {
  formatFingerprint,
  readOpenPgpCard,
  setOpenPgpUif,
} from "../../utils/passkey/openpgp";
import { encodeTlv } from "../../utils/passkey/tlv";

function cardCommands(): SendApdu {
  const aid = hexToBytes("D276000124010304ABCD00000001");
  const fingerprintData = new Uint8Array(60).fill(0x11);
  const applicationData = concatBytes(
    encodeTlv(0x4f, aid),
    encodeTlv(
      0x73,
      concatBytes(
        encodeTlv(0xc5, fingerprintData),
        encodeTlv(0xd6, new Uint8Array([1, 0x20])),
        encodeTlv(0xd7, new Uint8Array([0, 0x20])),
        encodeTlv(0xd8, new Uint8Array([2, 0x20])),
      ),
    ),
  );
  const cardholder = encodeTlv(0x5b, utf8Encode("Test User"));
  return async (capdu) => {
    if (capdu === "00CA006E00") return `${bytesToHex(applicationData)}9000`;
    if (capdu === "00CA006500") return `${bytesToHex(cardholder)}9000`;
    if (capdu === "00CA5F5000") return `${bytesToHex(utf8Encode("https://example.test/key"))}9000`;
    if (capdu === "00CA010200") return "0A9000";
    return "9000";
  };
}

describe("OpenPGP parsing", () => {
  it("reads card details and touch policies", async () => {
    const card = await readOpenPgpCard(cardCommands());
    expect(card).toMatchObject({
      version: "3.4",
      manufacturerId: "ABCD",
      serialNumber: "00000001",
      cardholder: "Test User",
      publicKeyUrl: "https://example.test/key",
      cacheTime: 10,
    });
    expect(card.fingerprints.signature).toBe(
      "1111 1111 1111 1111 1111 1111 1111 1111 1111 1111",
    );
    expect(card.policies).toEqual({
      signature: "on",
      encryption: "off",
      authentication: "permanent",
    });
  });

  it("formats empty and populated fingerprints", () => {
    expect(formatFingerprint(new Uint8Array(20))).toBe("Not set");
    expect(formatFingerprint(new Uint8Array([0xab, 0xcd]))).toBe("ABCD");
  });

  it("writes the UIF as policy plus button confirmation", async () => {
    const commands: string[] = [];
    const send: SendApdu = async (capdu) => {
      commands.push(capdu);
      return "9000";
    };
    await setOpenPgpUif(send, "signature", "on", "12345678");
    expect(commands.at(-1)).toBe("00DA00D6020120");
  });
});
