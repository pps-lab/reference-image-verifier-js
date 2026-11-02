// Small byte helpers shared by the parsers.

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function hex(bytes: Uint8Array, sep = ""): string {
  const out: string[] = [];
  for (const b of bytes) out.push(b.toString(16).padStart(2, "0"));
  return out.join(sep);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * WebCrypto's types reject Uint8Array<ArrayBufferLike>; nothing here ever
 * uses a SharedArrayBuffer, so the assertion is safe.
 */
export const bufferSource = (u: Uint8Array): Uint8Array<ArrayBuffer> =>
  u as Uint8Array<ArrayBuffer>;

export async function sha512(...parts: Uint8Array[]): Promise<Uint8Array> {
  const data = parts.length === 1 ? parts[0]! : concat(...parts);
  return new Uint8Array(
    await crypto.subtle.digest("SHA-512", bufferSource(data)),
  );
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", bufferSource(bytes)),
  );
}

/** Big-endian readers. Out-of-range reads yield NaN-free garbage, so callers bounds-check first. */
export function u16(b: Uint8Array, o: number): number {
  return ((b[o]! << 8) | b[o + 1]!) >>> 0;
}
export function u32(b: Uint8Array, o: number): number {
  return (
    ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0
  );
}
export function u64(b: Uint8Array, o: number): number {
  // Safe for anything a photo file can hold (< 2^53).
  return u32(b, o) * 0x100000000 + u32(b, o + 4);
}
export function ascii(b: Uint8Array, o: number, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += String.fromCharCode(b[o + i] ?? 0);
  return s;
}
export function uuidString(b: Uint8Array, o = 0): string {
  const h = hex(b.subarray(o, o + 16));
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Thrown for malformed input. Every other error is a bug or a platform failure. */
export class ParseError extends Error {
  override readonly name = "ParseError";
}
