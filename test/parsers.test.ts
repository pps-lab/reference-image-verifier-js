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
