import { PasskeyError } from "./apdu";

// Self-contained DES and two/three-key Triple DES (EDE, ECB) used by the PIV
// management-key challenge/response. Web Crypto does not expose DES, and a
// full crypto dependency is not warranted for a single 8-byte block operation.

const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
  27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38,
  30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
] as const;

const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27,
  20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56,
  34, 53, 46, 42, 50, 36, 29, 32,
] as const;

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] as const;

const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38,
  30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47,
  39, 31, 23, 15, 7,
] as const;

const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14,
  54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60,
  28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1,
  41, 9, 49, 17, 57, 25,
] as const;

const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15,
  16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28,
  29, 28, 29, 30, 31, 32, 1,
] as const;

const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14,
  32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
] as const;

const SBOXES: readonly (readonly number[])[] = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2,
    13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7,
    3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2,
    8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6,
    9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6,
    10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5,
    10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15,
    0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14,
    5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7,
    13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5,
    6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12,
    9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1,
    13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9,
    1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8,
    0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3,
    7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13,
    15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

function bitsOf(bytes: Uint8Array): number[] {
  const bits = new Array<number>(bytes.length * 8);
  let index = 0;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    for (let bit = 7; bit >= 0; bit--) {
      bits[index++] = (byte >> bit) & 1;
    }
  }
  return bits;
}

function bytesOf(bits: readonly number[]): Uint8Array {
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bytes.length; i++) {
    let value = 0;
    for (let bit = 0; bit < 8; bit++) {
      value = (value << 1) | bits[i * 8 + bit]!;
    }
    bytes[i] = value;
  }
  return bytes;
}

function permute(bits: readonly number[], table: readonly number[]): number[] {
  const result = new Array<number>(table.length);
  for (let i = 0; i < table.length; i++) {
    result[i] = bits[table[i]! - 1]!;
  }
  return result;
}

function keySchedule(key: Uint8Array): number[][] {
  const permuted = permute(bitsOf(key), PC1);
  let left = permuted.slice(0, 28);
  let right = permuted.slice(28, 56);
  const subkeys: number[][] = [];
  for (const shift of SHIFTS) {
    left = [...left.slice(shift), ...left.slice(0, shift)];
    right = [...right.slice(shift), ...right.slice(0, shift)];
    subkeys.push(permute([...left, ...right], PC2));
  }
  return subkeys;
}

function desBlock(
  block: Uint8Array,
  subkeys: number[][],
  decrypt: boolean,
): Uint8Array {
  const permuted = permute(bitsOf(block), IP);
  let left = permuted.slice(0, 32);
  let right = permuted.slice(32, 64);
  const order = decrypt ? [...subkeys].reverse() : subkeys;
  for (const subkey of order) {
    const expanded = permute(right, E);
    const mixed = new Array<number>(48);
    for (let i = 0; i < 48; i++) {
      mixed[i] = expanded[i]! ^ subkey[i]!;
    }
    const substituted: number[] = [];
    for (let box = 0; box < 8; box++) {
      const offset = box * 6;
      const row = (mixed[offset]! << 1) | mixed[offset + 5]!;
      const column =
        (mixed[offset + 1]! << 3) |
        (mixed[offset + 2]! << 2) |
        (mixed[offset + 3]! << 1) |
        mixed[offset + 4]!;
      const value = SBOXES[box]![row * 16 + column]!;
      substituted.push(
        (value >> 3) & 1,
        (value >> 2) & 1,
        (value >> 1) & 1,
        value & 1,
      );
    }
    const mixedFunction = permute(substituted, P);
    const nextRight = new Array<number>(32);
    for (let i = 0; i < 32; i++) {
      nextRight[i] = left[i]! ^ mixedFunction[i]!;
    }
    left = right;
    right = nextRight;
  }
  return bytesOf(permute([...right, ...left], FP));
}

/** Encrypts one 8-byte block with DES-EDE (two-key or three-key Triple DES). */
export function tripleDesEncryptBlock(
  block: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  if (block.length !== 8) {
    throw new PasskeyError(
      "Triple DES operates on 8-byte blocks.",
      "DES_BLOCK",
    );
  }
  if (key.length !== 16 && key.length !== 24) {
    throw new PasskeyError(
      "A PIV management key must be 16 or 24 bytes long.",
      "DES_KEY",
    );
  }
  const first = key.slice(0, 8);
  const second = key.slice(8, 16);
  const third = key.length === 24 ? key.slice(16, 24) : first;
  let result = desBlock(block, keySchedule(first), false);
  result = desBlock(result, keySchedule(second), true);
  return desBlock(result, keySchedule(third), false);
}
