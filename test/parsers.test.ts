// Tests that need no fixtures; this is what CI exercises.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  verifyReferenceImage,
  parseJpeg,
  isJpeg,
  isHeif,
  readExif,
  ParseError,
} from "../src/index.ts";
import { readTLV, children, oid, integerHex, time, TAG } from "../src/asn1.ts";

const jpeg = (...segments: number[][]) =>
  Uint8Array.from([0xff, 0xd8, ...segments.flat(), 0xff, 0xd9]);
const app = (marker: number, payload: number[]) => {
  const len = payload.length + 2;
  return [0xff, marker, len >> 8, len & 0xff, ...payload];
};

test("garbage input yields an error verdict, never a throw", async () => {
  const { report, processedJpeg } = await verifyReferenceImage(
    new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
  );
  assert.equal(report.verdict.status, "error");
  assert.equal(processedJpeg, null);
  assert.match(report.verdict.reasons[0]!, /Unrecognised file/);
  assert.equal(report.error?.name, "ParseError");
});

test("empty input", async () => {
  const { report } = await verifyReferenceImage(new Uint8Array());
  assert.equal(report.verdict.status, "error");
  assert.equal(report.verdict.reasons[0], "The file is empty.");
});

test("other file types are named in the error", async () => {
  const enc = (s: string) => Array.from(s, (c) => c.charCodeAt(0));
  for (const [bytes, re] of [
    [[0x89, ...enc("PNG\r\n\x1a\n"), 0, 0, 0, 0], /PNG image/],
    [enc("GIF89a\0\0\0\0"), /GIF image/],
    [enc("RIFF\0\0\0\0WEBPVP8 "), /WebP image/],
  ] as const) {
    const { report } = await verifyReferenceImage(Uint8Array.from(bytes));
    assert.equal(report.verdict.status, "error");
    assert.match(report.verdict.reasons[0]!, re);
  }
});

/** Big-endian TIFF with optional Make and an Exif IFD with an optional MakerNote. */
function tiff(opts: { make?: string; makerNote?: number[] }): number[] {
  const out: number[] = [];
  const u16 = (v: number) => out.push(v >> 8, v & 0xff);
  const u32 = (v: number) =>
    out.push(v >>> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  const make =
    opts.make === undefined
      ? null
      : [...new TextEncoder().encode(opts.make), 0];
  const n0 = (make ? 1 : 0) + 1;
  const ifd0End = 8 + 2 + 12 * n0 + 4;
  const makeOff = ifd0End;
  const exifOff = makeOff + (make?.length ?? 0);
  const mn = opts.makerNote;
  const mnOff = exifOff + 2 + (mn ? 12 : 0) + 4;
  const entry = (tag: number, type: number, count: number, value: number) => {
    u16(tag);
    u16(type);
    u32(count);
    u32(value);
  };
  out.push(0x4d, 0x4d, 0, 0x2a);
  u32(8);
  u16(n0);
  if (make) entry(0x010f, 2, make.length, makeOff);
  entry(0x8769, 4, 1, exifOff);
  u32(0);
  if (make) out.push(...make);
  u16(mn ? 1 : 0);
  if (mn) entry(0x927c, 7, mn.length, mnOff);
  u32(0);
  if (mn) out.push(...mn);
  return out;
}

/** "Apple iOS" MakerNote, optionally with the Reference Image flag (tag 0x0063). */
function appleMakerNote(flag?: number): number[] {
  const out = [...new TextEncoder().encode("Apple iOS\0"), 0, 1, 0x4d, 0x4d];
  if (flag === undefined) return [...out, 0, 0];
  return [
    ...out,
    0,
    1,
    0,
    0x63,
    0,
    4,
    0,
    0,
    0,
    1,
    flag >>> 24,
    (flag >> 16) & 0xff,
    (flag >> 8) & 0xff,
    flag & 0xff,
  ];
}

const exifJpeg = (t: number[]) =>
  jpeg(app(0xe1, [...new TextEncoder().encode("Exif\0\0"), ...t]));

test("a JPEG without provenance explains why from its Exif", async () => {
  const cases: [Uint8Array, RegExp][] = [
    [
      jpeg(app(0xe0, [0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0])),
      /No readable Exif metadata/,
    ],
    [exifJpeg(tiff({ make: "Canon" })), /Camera make is "Canon", not Apple/],
    [exifJpeg(tiff({})), /No camera make/],
    [exifJpeg(tiff({ make: "Apple" })), /no MakerNote \(0x927C\)/],
    [
      exifJpeg(
        tiff({
          make: "Apple",
          makerNote: [...new TextEncoder().encode("Nikon\0\0\0\0\0\0\0\0\0")],
        }),
      ),
      /MakerNote is not Apple's/,
    ],
    [
      exifJpeg(tiff({ make: "Apple", makerNote: appleMakerNote() })),
      /no Reference Image flag/,
    ],
    [
      exifJpeg(tiff({ make: "Apple", makerNote: appleMakerNote(3) })),
      /is 3, not 8/,
    ],
    [
      exifJpeg(tiff({ make: "Apple", makerNote: appleMakerNote(8) })),
      /signed data is missing/,
    ],
  ];
  for (const [bytes, re] of cases) {
    const { report } = await verifyReferenceImage(bytes);
    assert.equal(report.verdict.status, "not-reference-image");
    assert.match(report.verdict.reasons[0]!, /No Apple provenance APP3 chunks/);
    assert.match(report.verdict.reasons[1]!, re);
  }
});

test("readExif reports the MakerNote kind and flag", () => {
  assert.equal(
    readExif(Uint8Array.from(tiff({ make: "Apple" }))).makerNote,
    null,
  );
  const e = readExif(
    Uint8Array.from(tiff({ make: "Apple", makerNote: appleMakerNote(8) })),
  );
  assert.equal(e.make, "Apple");
  assert.equal(e.makerNote, "apple");
  assert.equal(e.appleReferenceFlag, 8);
});

test("a plain JPEG without provenance chunks is not a reference image", async () => {
  const bytes = jpeg(
    app(0xe0, [0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]),
  );
  assert.ok(isJpeg(bytes));
  assert.ok(!isHeif(bytes));
  const { report } = await verifyReferenceImage(bytes, { fileName: "x.jpg" });
  assert.equal(report.verdict.status, "not-reference-image");
  assert.equal(report.file.container, "jpeg");
  assert.equal(report.file.name, "x.jpg");
  assert.equal(report.file.format?.jfifVersion, "1.01");
  assert.equal(report.carrier, null);
});

test("a minimal HEIF without a provenance item is not a reference image", async () => {
  const box = (type: string, body: number[]) => {
    const size = 8 + body.length;
    return [
      size >>> 24,
      (size >> 16) & 0xff,
      (size >> 8) & 0xff,
      size & 0xff,
      ...new TextEncoder().encode(type),
      ...body,
    ];
  };
  const ftyp = box("ftyp", [...new TextEncoder().encode("heic"), 0, 0, 0, 0]);
  const meta = box("meta", [0, 0, 0, 0, ...box("pitm", [0, 0, 0, 0, 0, 1])]);
  const bytes = Uint8Array.from([...ftyp, ...meta]);
  assert.ok(isHeif(bytes));
  const { report } = await verifyReferenceImage(bytes);
  assert.equal(report.verdict.status, "not-reference-image");
  assert.equal(report.file.container, "heif");
  assert.equal(report.file.brand, "heic");
});

test("parseJpeg walks segments and rejects truncation", () => {
  const bytes = jpeg(app(0xe1, [1, 2, 3]), app(0xfe, [0x41]));
  const p = parseJpeg(bytes);
  assert.deepEqual(
    p.segments.map((s) => s.name),
    ["SOI", "APP1", "COM", "EOI"],
  );
  assert.equal(p.trailingBytes, 0);
  assert.throws(() => parseJpeg(bytes.subarray(0, 6)), ParseError);
  assert.throws(() => parseJpeg(new Uint8Array([0, 0, 0, 0, 0])), ParseError);
});

test("DER: TLV, OID, INTEGER and times", () => {
  // SEQUENCE { OID 1.2.840.113549.1.1.1, INTEGER 0x00FF, UTCTime 260318191220Z }
  const der = Uint8Array.from([
    0x30,
    0x1e,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x02,
    0x02,
    0x00,
    0xff,
    0x17,
    0x0d,
    ...new TextEncoder().encode("260318191220Z"),
  ]);
  const seq = readTLV(der, 0);
  assert.equal(seq.tag, TAG.SEQUENCE);
  const [o, i, t] = children(der, seq);
  assert.equal(oid(der, o!), "1.2.840.113549.1.1.1");
  assert.equal(integerHex(der, i!), "FF");
  assert.equal(time(der, t!).toISOString(), "2026-03-18T19:12:20.000Z");
  // Long-form tag (0x1f) and a 5-byte length are both rejected.
  assert.throws(() => readTLV(Uint8Array.of(0x1f, 0x01, 0x00), 0), ParseError);
  assert.throws(
    () => readTLV(Uint8Array.of(0x04, 0x85, 1, 1, 1, 1, 1), 0),
    ParseError,
  );
  assert.throws(() => readTLV(der.subarray(0, 10), 0), ParseError);
});

test("readExif is best-effort and never throws", () => {
  assert.equal(readExif(new Uint8Array()).appleReferenceFlag, null);
  assert.equal(
    readExif(new Uint8Array([0x4d, 0x4d, 0, 0x2a, 0, 0, 0, 8])).make,
    null,
  );
});

test("invalid `now` is a programmer error", async () => {
  await assert.rejects(
    verifyReferenceImage(new Uint8Array(), { now: "not a date" }),
    RangeError,
  );
});
