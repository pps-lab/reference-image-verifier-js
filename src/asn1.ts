// Minimal DER reader: enough for X.509 certificates and Apple's signature
// containers. Every node records absolute offsets into the source buffer so
// callers can hash or display exact byte ranges.

import { ParseError, hex } from "./util.ts";

export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8String: 0x0c,
  PrintableString: 0x13,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export interface TLV {
  tag: number;
  constructed: boolean;
  /** Offset of the tag byte. */
  start: number;
  /** Content start. */
  cStart: number;
  /** Content end (exclusive). */
  cEnd: number;
  /** End of the whole TLV (exclusive). */
  end: number;
  length: number;
}

/** Read one TLV at `off`. */
export function readTLV(buf: Uint8Array, off: number): TLV {
  if (off + 2 > buf.length) throw new ParseError("DER: truncated header");
  const tag = buf[off]!;
  if ((tag & 0x1f) === 0x1f)
    throw new ParseError("DER: long-form tags unsupported");
  let i = off + 1;
  let len = buf[i++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new ParseError("DER: bad length");
    if (i + n > buf.length) throw new ParseError("DER: truncated length");
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!;
  }
  if (i + len > buf.length) throw new ParseError("DER: length exceeds buffer");
  return {
    tag,
    constructed: (tag & 0x20) !== 0,
    start: off,
    cStart: i,
    cEnd: i + len,
    end: i + len,
    length: len,
  };
}

export function children(buf: Uint8Array, node: TLV): TLV[] {
  const out: TLV[] = [];
  let o = node.cStart;
  while (o < node.cEnd) {
    const c = readTLV(buf, o);
    out.push(c);
    o = c.end;
  }
  return out;
}

export const bytesOf = (buf: Uint8Array, node: TLV): Uint8Array =>
  buf.subarray(node.cStart, node.cEnd);
export const rawOf = (buf: Uint8Array, node: TLV): Uint8Array =>
  buf.subarray(node.start, node.end);

export function expect(node: TLV, tag: number, what: string): TLV {
  if (node.tag !== tag)
    throw new ParseError(
      `DER: expected ${what} (tag 0x${tag.toString(16)}), got 0x${node.tag.toString(16)}`,
    );
  return node;
}

export function oid(buf: Uint8Array, node: TLV): string {
  expect(node, TAG.OID, "OID");
  const b = bytesOf(buf, node);
  const parts: number[] = [];
  let v = 0;
  for (const x of b) {
    v = v * 128 + (x & 0x7f);
    if (!(x & 0x80)) {
      if (parts.length === 0) {
        const first = Math.min(2, Math.floor(v / 40));
        parts.push(first, v - 40 * first);
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

/** INTEGER as uppercase hex without the sign-padding byte (serials). */
export function integerHex(buf: Uint8Array, node: TLV): string {
  expect(node, TAG.INTEGER, "INTEGER");
  let b = bytesOf(buf, node);
  if (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return hex(b).toUpperCase();
}

export function smallInt(buf: Uint8Array, node: TLV): number {
  expect(node, TAG.INTEGER, "INTEGER");
  const b = bytesOf(buf, node);
  if (b.length > 6) throw new ParseError("DER: INTEGER too large");
  let v = 0;
  for (const x of b) v = v * 256 + x;
  return v;
}

/** BIT STRING payload without the leading unused-bits byte. */
export function bitString(buf: Uint8Array, node: TLV): Uint8Array {
  expect(node, TAG.BIT_STRING, "BIT STRING");
  const b = bytesOf(buf, node);
  if (b[0] !== 0) throw new ParseError("DER: BIT STRING with unused bits");
  return b.subarray(1);
}

export function time(buf: Uint8Array, node: TLV): Date {
  const s = new TextDecoder().decode(bytesOf(buf, node));
  let m: RegExpExecArray | null;
  if (
    node.tag === TAG.UTCTime &&
    (m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s))
  ) {
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(
      Date.UTC(year, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +(m[6] ?? 0)),
    );
  }
  if (
    node.tag === TAG.GeneralizedTime &&
    (m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(\.\d+)?Z$/.exec(s))
  ) {
    return new Date(
      Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +(m[6] ?? 0)),
    );
  }
  throw new ParseError(`DER: unsupported time ${JSON.stringify(s)}`);
}

// --- tiny DER writer (only what the RSA SPKI wrapper needs) ---
function encodeLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

export function der(tag: number, ...contents: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of contents) total += c.length;
  const head = [tag, ...encodeLength(total)];
  const out = new Uint8Array(head.length + total);
  out.set(head, 0);
  let o = head.length;
  for (const c of contents) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}
