import { PasskeyError } from "./apdu";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(value: string): Uint8Array {
  const input = value
    .trim()
    .replace(/[\s-]/g, "")
    .replace(/=+$/g, "")
    .toUpperCase();
  if (input.length === 0) {
    throw new PasskeyError("The secret is empty.", "BASE32_EMPTY");
  }
  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const character of input) {
    const index = ALPHABET.indexOf(character);
    if (index < 0) {
      throw new PasskeyError("The secret is not valid Base32.", "BASE32_INVALID");
    }
    buffer = (buffer << 5) | index;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1;
  }
  if (output.length === 0) {
    throw new PasskeyError("The secret is too short.", "BASE32_SHORT");
  }
  return new Uint8Array(output);
}
