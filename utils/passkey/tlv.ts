import { PasskeyError } from "./apdu";

export interface Tlv {
  tag: number;
  value: Uint8Array;
}

function readTag(data: Uint8Array, offset: number): { tag: number; next: number } {
  if (offset >= data.length) {
    throw new PasskeyError("Malformed TLV data.", "TLV_TAG");
  }
  let tag = data[offset]!;
  let next = offset + 1;
  if ((tag & 0x1f) === 0x1f) {
    let count = 1;
    while (next < data.length && count < 3) {
      const byte = data[next++]!;
      tag = (tag << 8) | byte;
      count++;
      if ((byte & 0x80) === 0) break;
    }
    if ((data[next - 1]! & 0x80) !== 0) {
      throw new PasskeyError("Malformed TLV tag.", "TLV_TAG");
    }
  }
  return { tag, next };
}

function readLength(data: Uint8Array, offset: number): { length: number; next: number } {
  if (offset >= data.length) {
    throw new PasskeyError("Malformed TLV data.", "TLV_LENGTH");
  }
  const first = data[offset]!;
  if ((first & 0x80) === 0) {
    return { length: first, next: offset + 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 3) {
    throw new PasskeyError("Unsupported TLV length.", "TLV_LENGTH");
  }
  if (offset + 1 + count > data.length) {
    throw new PasskeyError("Malformed TLV length.", "TLV_LENGTH");
  }
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = length * 256 + data[offset + 1 + i]!;
  }
  return { length, next: offset + 1 + count };
}

export function parseTlv(data: Uint8Array): Tlv[] {
  const result: Tlv[] = [];
  let offset = 0;
  while (offset < data.length) {
    const tag = readTag(data, offset);
    const length = readLength(data, tag.next);
    const end = length.next + length.length;
    if (end > data.length) {
      throw new PasskeyError("Malformed TLV value.", "TLV_VALUE");
    }
    result.push({ tag: tag.tag, value: data.slice(length.next, end) });
    offset = end;
  }
  return result;
}

export function findTlv(list: Tlv[], tag: number): Tlv | undefined {
  return list.find((item) => item.tag === tag);
}

export function nestedTlv(list: Tlv[], tag: number): Tlv[] | undefined {
  const item = findTlv(list, tag);
  if (!item) return undefined;
  return parseTlv(item.value);
}

export function encodeTlv(tag: number, value: Uint8Array): Uint8Array {
  if (tag > 0xffffff) {
    throw new PasskeyError("Unsupported TLV tag.", "TLV_TAG");
  }
  const tagBytes: number[] = [];
  if (tag <= 0xff) {
    tagBytes.push(tag);
  } else if (tag <= 0xffff) {
    tagBytes.push((tag >> 8) & 0xff, tag & 0xff);
  } else {
    tagBytes.push((tag >> 16) & 0xff, (tag >> 8) & 0xff, tag & 0xff);
  }
  const lengthBytes: number[] = [];
  if (value.length <= 0x7f) {
    lengthBytes.push(value.length);
  } else if (value.length <= 0xff) {
    lengthBytes.push(0x81, value.length);
  } else if (value.length <= 0xffff) {
    lengthBytes.push(0x82, (value.length >> 8) & 0xff, value.length & 0xff);
  } else {
    throw new PasskeyError("TLV value is too long.", "TLV_TOO_LONG");
  }
  const result = new Uint8Array(tagBytes.length + lengthBytes.length + value.length);
  result.set(tagBytes, 0);
  result.set(lengthBytes, tagBytes.length);
  result.set(value, tagBytes.length + lengthBytes.length);
  return result;
}
