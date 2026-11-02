// Minimal ISOBMFF/HEIF reader: finds the Apple provenance item
// (type "uri ", uri tag:apple.com,2025:photo:metadata:provenance:processedimage)
// and returns its bytes plus a few facts about the primary image.

import { ParseError, u16, u32, u64, ascii } from "./util.ts";
import { readExif, type ExifSummary } from "./exif.ts";

/** Item URI of the processed image inside a HEIC. */
export const PROVENANCE_URI =
  "tag:apple.com,2025:photo:metadata:provenance:processedimage";

export const isHeif = (b: Uint8Array): boolean =>
  b.length > 12 && ascii(b, 4, 4) === "ftyp";

interface IsoBox {
  type: string;
  offset: number;
  size: number;
  start: number;
  end: number;
}

function* boxes(b: Uint8Array, start: number, end: number): Generator<IsoBox> {
  let o = start;
  while (o + 8 <= end) {
    let size = u32(b, o);
    const type = ascii(b, o + 4, 4);
    let hdr = 8;
    if (size === 1) {
      if (o + 16 > end) throw new ParseError(`HEIF: truncated box at ${o}`);
      size = u64(b, o + 8);
      hdr = 16;
    } else if (size === 0) size = end - o;
    if (size < hdr || o + size > end)
      throw new ParseError(`HEIF: bad box ${type} at ${o}`);
    yield { type, offset: o, size, start: o + hdr, end: o + size };
    o += size;
  }
}

function cstring(b: Uint8Array, o: number, end: number) {
  let e = o;
  while (e < end && b[e] !== 0) e++;
  return { str: ascii(b, o, e - o), next: Math.min(e + 1, end) };
}

export interface HeifItem {
  id: number;
  type: string;
  name: string;
  uri?: string;
  contentType?: string;
}

export interface HeifLocation {
  method: number;
  extents: { offset: number; length: number }[];
}

export interface HeifInfo {
  brand: string;
  primaryItemId: number | null;
  items: Map<number, HeifItem>;
  locations: Map<number, HeifLocation>;
  refs: { type: string; from: number; to: number[] }[];
  properties: { type: string; width?: number; height?: number }[];
  /** item id → 1-based property indices */
  assoc: Map<number, number[]>;
  topLevel: { type: string; offset: number; size: number }[];
}

export function parseHeif(b: Uint8Array): HeifInfo {
  if (!isHeif(b)) throw new ParseError("not an ISOBMFF/HEIF file");
  const top = [...boxes(b, 0, b.length)];
  const ftyp = top.find((x) => x.type === "ftyp");
  if (!ftyp) throw new ParseError("HEIF: no ftyp box");
  const meta = top.find((x) => x.type === "meta");
  if (!meta) throw new ParseError("HEIF: no meta box");
  const info: HeifInfo = {
    brand: ascii(b, ftyp.start, 4),
    primaryItemId: null,
    items: new Map(),
    locations: new Map(),
    refs: [],
    properties: [],
    assoc: new Map(),
    topLevel: top.map(({ type, offset, size }) => ({ type, offset, size })),
  };
  for (const bx of boxes(b, meta.start + 4, meta.end)) {
    const v = b[bx.start] ?? 0;
    const body = bx.start + 4;
    if (bx.type === "pitm")
      info.primaryItemId = v === 0 ? u16(b, body) : u32(b, body);
    else if (bx.type === "iinf") {
      const first = body + (v === 0 ? 2 : 4);
      for (const e of boxes(b, first, bx.end)) {
        if (e.type !== "infe") continue;
        const ev = b[e.start] ?? 0;
        let o = e.start + 4;
        if (ev < 2) continue;
        const id = ev === 2 ? u16(b, o) : u32(b, o);
        o += ev === 2 ? 2 : 4;
        o += 2; // protection index
        const itemType = ascii(b, o, 4);
        o += 4;
        const name = cstring(b, o, e.end);
        const item: HeifItem = { id, type: itemType, name: name.str };
        if (itemType === "uri ") item.uri = cstring(b, name.next, e.end).str;
        if (itemType === "mime")
          item.contentType = cstring(b, name.next, e.end).str;
        info.items.set(id, item);
      }
    } else if (bx.type === "iloc") {
      const offSize = b[body]! >> 4,
        lenSize = b[body]! & 15,
        baseSize = b[body + 1]! >> 4;
      const idxSize = v >= 1 ? b[body + 1]! & 15 : 0;
      let o = body + 2;
      const count = v < 2 ? u16(b, o) : u32(b, o);
      o += v < 2 ? 2 : 4;
      const rd = (n: number): number => {
        const x =
          n === 8 ? u64(b, o) : n === 4 ? u32(b, o) : n === 2 ? u16(b, o) : 0;
        o += n;
        return x;
      };
      for (let k = 0; k < count; k++) {
        const id = v < 2 ? u16(b, o) : u32(b, o);
        o += v < 2 ? 2 : 4;
        let method = 0;
        if (v >= 1) {
          method = u16(b, o) & 15;
          o += 2;
        }
        o += 2; // data_reference_index
        const base = rd(baseSize);
        const extentCount = u16(b, o);
        o += 2;
        const extents: HeifLocation["extents"] = [];
        for (let x = 0; x < extentCount; x++) {
          if (v >= 1 && idxSize > 0) rd(idxSize);
          const off = rd(offSize),
            len = rd(lenSize);
          extents.push({ offset: base + off, length: len });
        }
        info.locations.set(id, { method, extents });
      }
    } else if (bx.type === "iref") {
      for (const r of boxes(b, body, bx.end)) {
        const from = v === 0 ? u16(b, r.start) : u32(b, r.start);
        let o = r.start + (v === 0 ? 2 : 4);
        const n = u16(b, o);
        o += 2;
        const to: number[] = [];
        for (let k = 0; k < n; k++) {
          to.push(v === 0 ? u16(b, o) : u32(b, o));
          o += v === 0 ? 2 : 4;
        }
        info.refs.push({ type: r.type, from, to });
      }
    } else if (bx.type === "iprp") {
      for (const p of boxes(b, bx.start, bx.end)) {
        if (p.type === "ipco") {
          for (const prop of boxes(b, p.start, p.end)) {
            const entry: HeifInfo["properties"][number] = { type: prop.type };
            if (prop.type === "ispe") {
              entry.width = u32(b, prop.start + 4);
              entry.height = u32(b, prop.start + 8);
            }
            info.properties.push(entry);
          }
        } else if (p.type === "ipma") {
          const pv = b[p.start] ?? 0,
            flags = u32(b, p.start) & 0xffffff;
          let o = p.start + 4;
          const n = u32(b, o);
          o += 4;
          for (let k = 0; k < n; k++) {
            const id = pv < 1 ? u16(b, o) : u32(b, o);
            o += pv < 1 ? 2 : 4;
            const c = b[o++] ?? 0;
            const idx: number[] = [];
            for (let x = 0; x < c; x++) {
              if (flags & 1) {
                idx.push(u16(b, o) & 0x7fff);
                o += 2;
              } else idx.push(b[o++]! & 0x7f);
            }
            info.assoc.set(id, idx);
          }
        }
      }
    }
  }
  return info;
}

export function itemBytes(
  b: Uint8Array,
  info: HeifInfo,
  id: number,
): Uint8Array {
  const loc = info.locations.get(id);
  if (!loc) throw new ParseError(`HEIF: item ${id} has no location`);
  if (loc.method !== 0)
    throw new ParseError(
      `HEIF: item ${id} uses construction method ${loc.method}`,
    );
  for (const e of loc.extents)
    if (e.offset + e.length > b.length)
      throw new ParseError("HEIF: item extent exceeds file");
  const only = loc.extents[0];
  if (loc.extents.length === 1 && only)
    return b.subarray(only.offset, only.offset + only.length);
  const total = loc.extents.reduce((n, e) => n + e.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const e of loc.extents) {
    out.set(b.subarray(e.offset, e.offset + e.length), o);
    o += e.length;
  }
  return out;
}

function primaryDimensions(info: HeifInfo) {
  const idx =
    info.primaryItemId === null
      ? []
      : (info.assoc.get(info.primaryItemId) ?? []);
  for (const i of idx) {
    const p = info.properties[i - 1];
    if (p?.type === "ispe")
      return { width: p.width ?? null, height: p.height ?? null };
  }
  return { width: null, height: null };
}

export interface HeifCarrier {
  kind: "heif-item";
  itemId: number;
  itemOffset: number | null;
  itemLength: number | null;
  extentCount: number;
  /** Whether the item is linked (cdsc) to the primary image. */
  describesPrimary: boolean;
  primaryItemId: number | null;
  /** The embedded processed JPEG. */
  data: Uint8Array;
}

/** Locate the provenance item. Returns null when the file has none. */
export function extractHeifProvenance(
  b: Uint8Array,
  info: HeifInfo,
): HeifCarrier | null {
  const item = [...info.items.values()].find(
    (it) => it.type === "uri " && it.uri === PROVENANCE_URI,
  );
  if (!item) return null;
  const loc = info.locations.get(item.id);
  const cdsc = info.refs.find((r) => r.type === "cdsc" && r.from === item.id);
  return {
    kind: "heif-item",
    itemId: item.id,
    itemOffset: loc?.extents[0]?.offset ?? null,
    itemLength: loc ? loc.extents.reduce((n, e) => n + e.length, 0) : null,
    extentCount: loc?.extents.length ?? 0,
    describesPrimary:
      !!cdsc &&
      info.primaryItemId !== null &&
      cdsc.to.includes(info.primaryItemId),
    primaryItemId: info.primaryItemId,
    data: itemBytes(b, info, item.id),
  };
}

export interface OuterHeifInfo {
  width: number | null;
  height: number | null;
  brand: string;
  primaryType: string | null;
  itemCount: number;
  exif: ExifSummary | null;
}

export function outerHeifInfo(b: Uint8Array, info: HeifInfo): OuterHeifInfo {
  const dims = primaryDimensions(info);
  let exif: ExifSummary | null = null;
  const exifItem = [...info.items.values()].find((it) => it.type === "Exif");
  if (exifItem) {
    try {
      const raw = itemBytes(b, info, exifItem.id);
      let o = 4 + u32(raw, 0);
      if (ascii(raw, o, 6) === "Exif\0\0") o += 6;
      exif = readExif(raw.subarray(o));
    } catch {
      exif = null;
    }
  }
  const primary =
    info.primaryItemId === null
      ? undefined
      : info.items.get(info.primaryItemId);
  return {
    ...dims,
    brand: info.brand,
    primaryType: primary?.type ?? null,
    itemCount: info.items.size,
    exif,
  };
}
