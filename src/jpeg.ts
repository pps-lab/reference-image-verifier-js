// JPEG marker walker, APP3 chunk reassembly and APP11 JUMBF box parsing.

import {
  ParseError,
  u16,
  u32,
  ascii,
  uuidString,
  concat,
  equalBytes,
  utf8,
} from "./util.ts";
import { readExif, type ExifSummary } from "./exif.ts";

/** APPn identifier of Apple's chunked provenance carrier in JPEG exports. */
export const CHUNKED_ID =
  "tag:apple.com,2025:chunked_binary_metadata:tag:apple.com,2025:photo:metadata:provenance:processedimage";

const NAMES: Record<number, string> = {
  0xc0: "SOF0",
  0xc1: "SOF1",
  0xc2: "SOF2",
  0xc4: "DHT",
  0xc8: "JPG",
  0xcc: "DAC",
  0xd8: "SOI",
  0xd9: "EOI",
  0xda: "SOS",
  0xdb: "DQT",
  0xdc: "DNL",
  0xdd: "DRI",
  0xe0: "APP0",
  0xe1: "APP1",
  0xe2: "APP2",
  0xe3: "APP3",
  0xe4: "APP4",
  0xe5: "APP5",
  0xe6: "APP6",
  0xe7: "APP7",
  0xe8: "APP8",
  0xe9: "APP9",
  0xea: "APP10",
  0xeb: "APP11",
  0xec: "APP12",
  0xed: "APP13",
  0xee: "APP14",
  0xef: "APP15",
  0xfe: "COM",
};

export interface JpegSegment {
  /** Marker byte after 0xFF, or null for the entropy-coded "scan" pseudo-segment. */
  marker: number | null;
  name: string;
  /** Absolute offset of the 0xFF marker byte. */
  offset: number;
  /** Length including the 2-byte marker. */
  length: number;
  payloadStart: number;
  payloadEnd: number;
}

export interface ParsedJpeg {
  segments: JpegSegment[];
  width: number | null;
  height: number | null;
  components: number | null;
  size: number;
  trailingBytes: number;
}

export const isJpeg = (b: Uint8Array): boolean =>
  b.length > 4 && b[0] === 0xff && b[1] === 0xd8;

/**
 * Walk the marker segments of a JPEG. Scan data (after SOS) is reported as a
 * pseudo-segment named "scan". Offsets are absolute; `length` includes the
 * 2-byte marker.
 */
export function parseJpeg(bytes: Uint8Array): ParsedJpeg {
  if (!isJpeg(bytes)) throw new ParseError("not a JPEG (missing SOI)");
  const segments: JpegSegment[] = [
    {
      marker: 0xd8,
      name: "SOI",
      offset: 0,
      length: 2,
      payloadStart: 2,
      payloadEnd: 2,
    },
  ];
  let i = 2;
  let width: number | null = null,
    height: number | null = null,
    components: number | null = null;
  while (i + 2 <= bytes.length) {
    if (bytes[i] !== 0xff)
      throw new ParseError(`JPEG: expected marker at ${i}`);
    const m = bytes[i + 1]!;
    if (m === 0xff) {
      i++;
      continue;
    } // fill byte
    if (m === 0xd9) {
      segments.push({
        marker: m,
        name: "EOI",
        offset: i,
        length: 2,
        payloadStart: i + 2,
        payloadEnd: i + 2,
      });
      i += 2;
      break;
    }
    if (m >= 0xd0 && m <= 0xd7) {
      i += 2;
      continue;
    }
    if (i + 4 > bytes.length)
      throw new ParseError(`JPEG: truncated segment at ${i}`);
    const len = u16(bytes, i + 2);
    const seg: JpegSegment = {
      marker: m,
      name: NAMES[m] ?? `0x${m.toString(16)}`,
      offset: i,
      length: 2 + len,
      payloadStart: i + 4,
      payloadEnd: i + 2 + len,
    };
    if (len < 2 || seg.payloadEnd > bytes.length)
      throw new ParseError(`JPEG: segment at ${i} exceeds file`);
    segments.push(seg);
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
      height = u16(bytes, seg.payloadStart + 1);
      width = u16(bytes, seg.payloadStart + 3);
      components = bytes[seg.payloadStart + 5] ?? null;
    }
    i = seg.payloadEnd;
    if (m === 0xda) {
      // Entropy-coded data runs to the next real marker (not FF00 / RSTn).
      let j = i;
      while (j + 1 < bytes.length) {
        const next = bytes[j + 1]!;
        if (
          bytes[j] === 0xff &&
          next !== 0 &&
          !(next >= 0xd0 && next <= 0xd7) &&
          next !== 0xff
        )
          break;
        j++;
      }
      segments.push({
        marker: null,
        name: "scan",
        offset: i,
        length: j - i,
        payloadStart: i,
        payloadEnd: j,
      });
      i = j;
    }
  }
  const eoi = segments.find((s) => s.name === "EOI");
  return {
    segments,
    width,
    height,
    components,
    size: bytes.length,
    trailingBytes: eoi ? bytes.length - eoi.payloadEnd : 0,
  };
}

// Coding process by SOFn marker (ISO/IEC 10918-1, table B.1).
const SOF_PROCESS: Record<number, string> = {
  0xc0: "Baseline DCT, Huffman",
  0xc1: "Extended sequential DCT, Huffman",
  0xc2: "Progressive DCT, Huffman",
  0xc3: "Lossless (sequential), Huffman",
  0xc5: "Differential sequential DCT, Huffman",
  0xc6: "Differential progressive DCT, Huffman",
  0xc7: "Differential lossless, Huffman",
  0xc9: "Extended sequential DCT, arithmetic",
  0xca: "Progressive DCT, arithmetic",
  0xcb: "Lossless (sequential), arithmetic",
  0xcd: "Differential sequential DCT, arithmetic",
  0xce: "Differential progressive DCT, arithmetic",
  0xcf: "Differential lossless, arithmetic",
};

export interface JpegFormat {
  standard: string;
  process: string | null;
  sofMarker: string | null;
  precision: number | null;
  components: number | null;
  subsampling: string | null;
  jfifVersion: string | null;
  exifVersion: string | null;
  restartInterval: number | null;
}

/**
 * Which flavour of JPEG this is: the coding process from the SOFn marker,
 * sample precision, chroma subsampling, and the JFIF / Exif versions declared
 * in APP0 / APP1. Purely descriptive; the signature does not depend on it.
 */
export function jpegFormat(bytes: Uint8Array, parsed: ParsedJpeg): JpegFormat {
  const out: JpegFormat = {
    standard: "ISO/IEC 10918-1 (JPEG)",
    process: null,
    sofMarker: null,
    precision: null,
    components: null,
    subsampling: null,
    jfifVersion: null,
    exifVersion: null,
    restartInterval: null,
  };
  const sof = parsed.segments.find(
    (s) => s.marker !== null && SOF_PROCESS[s.marker] !== undefined,
  );
  if (sof && sof.marker !== null) {
    out.sofMarker = NAMES[sof.marker] ?? `0x${sof.marker.toString(16)}`;
    out.process = SOF_PROCESS[sof.marker] ?? null;
    out.precision = bytes[sof.payloadStart] ?? null;
    const n = bytes[sof.payloadStart + 5] ?? 0;
    out.components = n;
    const f: [number, number][] = [];
    for (
      let k = 0;
      k < n && sof.payloadStart + 6 + 3 * k + 1 < bytes.length;
      k++
    ) {
      const hv = bytes[sof.payloadStart + 6 + 3 * k + 1]!;
      f.push([hv >> 4, hv & 15]);
    }
    if (n === 3 && f[1]?.join() === "1,1" && f[2]?.join() === "1,1") {
      const key = f[0]!.join("x");
      const names: Record<string, string> = {
        "1x1": "4:4:4",
        "2x1": "4:2:2",
        "1x2": "4:4:0",
        "2x2": "4:2:0",
      };
      out.subsampling = names[key] ?? `luma ${key}`;
    } else if (n === 1) out.subsampling = "greyscale";
  }
  const app0 = parsed.segments.find(
    (s) => s.marker === 0xe0 && ascii(bytes, s.payloadStart, 5) === "JFIF\0",
  );
  if (app0)
    out.jfifVersion = `${bytes[app0.payloadStart + 5]}.${String(bytes[app0.payloadStart + 6]).padStart(2, "0")}`;
  const exif = exifOf(bytes, parsed);
  if (exif) out.exifVersion = exif.exifVersion;
  const dri = parsed.segments.find((s) => s.marker === 0xdd);
  if (dri) out.restartInterval = u16(bytes, dri.payloadStart);
  return out;
}

function exifOf(bytes: Uint8Array, parsed: ParsedJpeg): ExifSummary | null {
  const app1 = parsed.segments.find(
    (s) => s.marker === 0xe1 && ascii(bytes, s.payloadStart, 6) === "Exif\0\0",
  );
  return app1
    ? readExif(bytes.subarray(app1.payloadStart + 6, app1.payloadEnd))
    : null;
}

/** Null-terminated ASCII identifier at the start of an APPn payload. */
export function segmentId(bytes: Uint8Array, seg: JpegSegment): string {
  let e = seg.payloadStart;
  while (e < seg.payloadEnd && bytes[e] !== 0 && e - seg.payloadStart < 200)
    e++;
  return ascii(bytes, seg.payloadStart, e - seg.payloadStart);
}

export interface ChunkedCarrier {
  kind: "app3-chunks";
  chunkCount: number;
  /** Bytes the APP3 segments occupy in the outer file, markers included. */
  carrierBytes: number;
  firstChunkOffset: number;
  /** The 4-byte field that precedes the JPEG (always 0 in observed files). */
  leadingField: number;
  /** The embedded processed JPEG. */
  data: Uint8Array;
}

/** Reassemble Apple's chunked_binary_metadata APP3 segments. */
export function extractChunkedProvenance(
  bytes: Uint8Array,
  parsed: ParsedJpeg,
): ChunkedCarrier | null {
  const idBytes = concat(utf8(CHUNKED_ID), Uint8Array.of(0));
  const chunks: {
    seq: number;
    total: number;
    data: Uint8Array;
    offset: number;
    length: number;
  }[] = [];
  for (const s of parsed.segments) {
    if (s.marker !== 0xe3) continue;
    const p = bytes.subarray(s.payloadStart, s.payloadEnd);
    if (
      p.length < idBytes.length + 4 ||
      !equalBytes(p.subarray(0, idBytes.length), idBytes)
    )
      continue;
    const h = idBytes.length;
    chunks.push({
      seq: u16(p, h),
      total: u16(p, h + 2),
      data: p.subarray(h + 4),
      offset: s.offset,
      length: s.length,
    });
  }
  const first = chunks[0];
  if (!first) return null;
  chunks.sort((a, b) => a.seq - b.seq);
  const total = first.total;
  if (chunks.length !== total || chunks.some((c, k) => c.seq !== first.seq + k))
    throw new ParseError(
      `APP3 provenance chunks incomplete: have ${chunks.length} of ${total}`,
    );
  const joined = concat(...chunks.map((c) => c.data));
  if (joined.length < 4)
    throw new ParseError("APP3 provenance payload too short");
  // Leading 4-byte field (always zero in observed files), then the JPEG.
  return {
    kind: "app3-chunks",
    chunkCount: chunks.length,
    carrierBytes: chunks.reduce((n, c) => n + c.length, 0),
    firstChunkOffset: first.offset,
    leadingField: u32(joined, 0),
    data: joined.subarray(4),
  };
}

export interface Box {
  offset: number;
  size: number;
  type: string;
  contentStart: number;
  contentEnd: number;
  /** Set for "uuid" boxes. */
  uuid?: string;
}

export interface JumbfSegment {
  instance: number;
  sequence: number;
  box: Box;
  segment: JpegSegment;
}

/** Parse a JUMBF-in-APP11 segment: "JP", instance, sequence, then one box. */
export function parseJumbfSegment(
  bytes: Uint8Array,
  seg: JpegSegment,
): JumbfSegment | null {
  const p = seg.payloadStart;
  if (ascii(bytes, p, 2) !== "JP") return null;
  const instance = u16(bytes, p + 2);
  const sequence = u32(bytes, p + 4);
  const box = parseBox(bytes, p + 8, seg.payloadEnd);
  return { instance, sequence, box, segment: seg };
}

export function parseBox(bytes: Uint8Array, off: number, limit: number): Box {
  if (off + 8 > limit) throw new ParseError(`JUMBF: truncated box at ${off}`);
  const size = u32(bytes, off);
  const type = ascii(bytes, off + 4, 4);
  if (size < 8 || off + size > limit)
    throw new ParseError(`JUMBF: bad box size ${size} at ${off}`);
  const box: Box = {
    offset: off,
    size,
    type,
    contentStart: off + 8,
    contentEnd: off + size,
  };
  if (type === "uuid") {
    if (size < 24) throw new ParseError(`JUMBF: uuid box too small at ${off}`);
    box.uuid = uuidString(bytes, off + 8);
    box.contentStart = off + 24;
  }
  return box;
}

export interface OuterJpegInfo {
  width: number | null;
  height: number | null;
  exif: ExifSummary | null;
  format: JpegFormat;
}

export function outerJpegInfo(
  bytes: Uint8Array,
  parsed: ParsedJpeg,
): OuterJpegInfo {
  return {
    width: parsed.width,
    height: parsed.height,
    exif: exifOf(bytes, parsed),
    format: jpegFormat(bytes, parsed),
  };
}
