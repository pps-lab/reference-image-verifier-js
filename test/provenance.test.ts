import { test } from "node:test";
import assert from "node:assert/strict";
import {
  verifyReferenceImage,
  parseCertificate,
  parseJpeg,
} from "../src/index.ts";
import type { Report } from "../src/index.ts";
import { readTLV, children } from "../src/asn1.ts";
import { concat } from "../src/util.ts";
import { hasFixture, loadFixture, NOW } from "./fixtures.ts";

const GOLD = {
  "IMG_0071.JPG": {
    size: 2496816,
    combined:
      "aa964ad91091ab5777ada52f1d86eab5060758831832776ea622ae6a06e3ffeb73e3d44ca121bf6916f15ba82b5580637c9e6961a7a7d9004bfa799b81b0b2b3",
    carrier: "app3-chunks",
  },
  "IMG_0073.HEIC": {
    size: 4365434,
    combined:
      "6a2b818ab2151353d8d3d54b303445c69674f2d894b9add58202b50718289e94625193003087f750d4a72a390977489e63dbc267f44795003342c5f45908c323",
    carrier: "heif-item",
  },
} as const;

const missing = (name: string) =>
  hasFixture(name) ? false : `fixture ${name} not present`;

for (const [name, g] of Object.entries(GOLD)) {
  test(
    `${name}: extraction, hashes, signature and chain`,
    { skip: missing(name) },
    async () => {
      const bytes = await loadFixture(name);
      const { report: r, processedJpeg } = await verifyReferenceImage(bytes, {
        now: NOW,
        fileName: name,
      });
      assert.equal(r.verdict.status, "pass", JSON.stringify(r.verdict));
      assert.equal(r.carrier?.kind, g.carrier);
      assert.equal(processedJpeg?.length, g.size);
      assert.equal(r.processed?.width, 3024);
      assert.equal(r.processed?.height, 4032);
      assert.deepEqual(r.hashing?.ranges.signatureParameters, [2245, 24402]);
      assert.deepEqual(r.hashing?.ranges.excluded, [2309, 7340]);
      assert.equal(r.hashing?.specVersion, "1.3");
      const f = r.processed.format;
      assert.deepEqual(
        [
          f.sofMarker,
          f.process,
          f.precision,
          f.subsampling,
          f.jfifVersion,
          f.exifVersion,
        ],
        ["SOF0", "Baseline DCT, Huffman", 8, "4:2:0", "1.01", "2.21"],
      );
      assert.equal(r.hashing?.combinedHash, g.combined);
      assert.deepEqual(
        [r.signature?.mldsa.valid, r.signature?.rsa.valid],
        [true, true],
      );
      assert.equal(
        r.signature?.signerSerial,
        "34419077115C715CD3035EF90C2EC950",
      );
      assert.equal(r.certificates.length, 3);
      assert.deepEqual(
        r.certificates.map((c) => c.role),
        ["signer", "issuing-ca", "root"],
      );
      for (const c of r.certificates.slice(0, 2)) {
        assert.ok(c.signature.valid && c.withinValidity, c.subject);
      }
      const root = r.certificates[2]!;
      assert.ok(root.isTrustAnchor);
      assert.equal(root.embeddedInFile, false);
      assert.equal(root.serial, "63244EB094AA7DB3150CF12216B4A4FC");
      assert.ok(root.withinValidity);
      assert.ok(root.signature.valid, "built-in root self-signature");
      assert.ok(r.chain?.reachesTrustAnchor);
      assert.ok(r.chain?.valid);
      assert.equal(r.boxes?.timestamps?.unix.length, 3);
      assert.ok((r.boxes?.signature.developedAtUnix ?? 0) > 1_700_000_000);
      assert.equal(r.boxes?.header?.entries.length, 2);
      assert.equal(r.chain?.developedWithinSignerValidity, true);
      JSON.stringify(r); // must be serialisable
    },
  );

  test(
    `${name}: trustAnchors with the real root certificate reports a full root entry`,
    { skip: missing(name) || missing("root.cer") },
    async () => {
      const root = await loadFixture("root.cer");
      const { report: r } = await verifyReferenceImage(
        await loadFixture(name),
        {
          now: NOW,
          trustAnchors: [root],
        },
      );
      assert.equal(r.verdict.status, "pass", JSON.stringify(r.verdict));
      const anchor = r.certificates[2]!;
      assert.equal(anchor.role, "root");
      assert.equal(anchor.serial, "63244EB094AA7DB3150CF12216B4A4FC");
      assert.ok(anchor.withinValidity);
      assert.ok(anchor.signature.valid, "root self-signature");
      assert.ok(anchor.isTrustAnchor);
    },
  );

  test(
    `${name}: a wrong trust anchor fails the chain`,
    { skip: missing(name) },
    async () => {
      // Use the signer certificate itself as the "root": the chain cannot end there.
      const bytes = await loadFixture(name);
      const { report: first, processedJpeg } = await verifyReferenceImage(
        bytes,
        { now: NOW },
      );
      const box = first.boxes!.signature;
      const bundle = processedJpeg!.subarray(
        box.bundleOffset,
        box.bundleOffset + box.bundleLength,
      );
      // SignatureParameters ::= SEQUENCE { version, alg, SEQUENCE OF Certificate }
      const outer = readTLV(bundle, 0);
      const list = children(bundle, outer)[2]!;
      const firstCert = children(bundle, list)[0]!;
      const leaf = await parseCertificate(bundle, firstCert.start);
      const { report: r } = await verifyReferenceImage(bytes, {
        now: NOW,
        trustAnchors: [leaf.der],
      });
      assert.equal(r.verdict.status, "fail");
      assert.ok(
        r.verdict.reasons.some((x) =>
          x.includes("does not end at a trusted root"),
        ),
        r.verdict.reasons.join("\n"),
      );
      assert.equal(r.chain?.reachesTrustAnchor, false);
    },
  );
}

test(
  "HEIC outer facts: dimensions, Exif, Reference Image flag",
  { skip: missing("IMG_0073.HEIC") },
  async () => {
    const { report: r } = await verifyReferenceImage(
      await loadFixture("IMG_0073.HEIC"),
      { now: NOW },
    );
    assert.equal(r.file.container, "heif");
    assert.ok(
      (r.file.width ?? 0) > 3024 && (r.file.height ?? 0) > 3024,
      `${r.file.width}x${r.file.height}`,
    );
    assert.equal(r.file.exif?.appleReferenceFlag, 8);
    assert.equal(r.carrier?.kind, "heif-item");
    assert.ok(r.carrier?.kind === "heif-item" && r.carrier.describesPrimary);
  },
);

test(
  "JPEG outer facts: dimensions and Reference Image flag",
  { skip: missing("IMG_0071.JPG") },
  async () => {
    const { report: r } = await verifyReferenceImage(
      await loadFixture("IMG_0071.JPG"),
      { now: NOW },
    );
    assert.deepEqual([r.file.width, r.file.height], [5712, 4284]);
    assert.equal(r.file.exif?.appleReferenceFlag, 8);
    assert.ok(r.carrier?.kind === "app3-chunks" && r.carrier.chunkCount === 39);
    assert.equal(r.file.format?.process, "Baseline DCT, Huffman");
    assert.equal(r.file.format?.exifVersion, "2.32");
  },
);

// Tamper matrix: flip one byte in each region of the processed JPEG,
// re-embedded into the outer file by patching in place.
async function flipInProcessed(name: string, pick: (r: Report) => number) {
  const bytes = new Uint8Array(await loadFixture(name));
  const { report, processedJpeg } = await verifyReferenceImage(bytes, {
    now: NOW,
  });
  const off = pick(report);
  // Locate the processed byte inside the outer file by searching for a unique
  // 32-byte window around it (chunk boundaries make a direct map awkward).
  const win = processedJpeg!.subarray(off - 16, off + 16);
  let hit = -1;
  outer: for (let i = 0; i <= bytes.length - 32; i++) {
    if (bytes[i] !== win[0]) continue;
    for (let k = 1; k < 32; k++) if (bytes[i + k] !== win[k]) continue outer;
    hit = i;
    break;
  }
  assert.ok(hit >= 0, "window not found in outer file");
  bytes[hit + 16]! ^= 0x01;
  return verifyReferenceImage(bytes, { now: NOW });
}

const REGIONS: Record<string, (r: Report) => number> = {
  "scan data (C)": (r) => r.hashing!.ranges.content[0] + 1000,
  "Exif (P)": (r) =>
    r.processed!.segments.find((s) => s.name === "APP1")!.offset + 40,
  "box-2 timestamp (P)": (r) =>
    r.boxes!.timestamps!.offset + r.boxes!.timestamps!.length - 2,
  "certificate bundle (S)": (r) => r.boxes!.signature.bundleOffset + 200,
};
for (const name of ["IMG_0071.JPG", "IMG_0073.HEIC"]) {
  for (const [region, pick] of Object.entries(REGIONS)) {
    test(
      `${name}: flipping a byte in ${region} fails both halves`,
      { skip: missing(name) },
      async () => {
        const { report: r } = await flipInProcessed(name, pick);
        assert.equal(r.verdict.status, "fail");
        assert.deepEqual(
          [r.signature?.mldsa.valid, r.signature?.rsa.valid],
          [false, false],
        );
      },
    );
  }
  test(
    `${name}: flipping a byte in the ML-DSA half fails only that half`,
    { skip: missing(name) },
    async () => {
      const { report: r } = await flipInProcessed(
        name,
        (r) => r.boxes!.signature.sigDerOffset + 100,
      );
      assert.equal(r.verdict.status, "fail");
      assert.deepEqual(
        [r.signature?.mldsa.valid, r.signature?.rsa.valid],
        [false, true],
      );
      assert.ok(r.chain?.valid, "chain must still verify");
    },
  );
}

test(
  "a real photo with its APP3 chunks removed is reported as stripped",
  { skip: missing("IMG_0071.JPG") },
  async () => {
    const bytes = await loadFixture("IMG_0071.JPG");
    const app3 = parseJpeg(bytes).segments.filter((s) => s.marker === 0xe3);
    const parts: Uint8Array[] = [];
    let at = 0;
    for (const s of app3) {
      parts.push(bytes.subarray(at, s.offset));
      at = s.offset + s.length;
    }
    const stripped = concat(...parts, bytes.subarray(at));
    const { report } = await verifyReferenceImage(stripped, { now: NOW });
    assert.equal(report.verdict.status, "not-reference-image");
    assert.equal(report.file.exif?.makerNote, "apple");
    assert.match(report.verdict.reasons[1]!, /signed data is missing/);
  },
);

test(
  "truncated input fails cleanly",
  { skip: missing("IMG_0071.JPG") },
  async () => {
    const bytes = await loadFixture("IMG_0071.JPG");
    // Cut inside the APP3 chunk region: the processed image is incomplete.
    const { report } = await verifyReferenceImage(
      bytes.subarray(0, 1_000_000),
      {
        now: NOW,
      },
    );
    assert.equal(report.verdict.status, "error");
    assert.match(report.verdict.reasons[0]!, /incomplete|exceeds/);
  },
);

test(
  "truncating the OUTER scan data does not affect the verdict (the signature binds only the embedded image)",
  { skip: missing("IMG_0071.JPG") },
  async () => {
    const bytes = await loadFixture("IMG_0071.JPG");
    const { report } = await verifyReferenceImage(
      bytes.subarray(0, 3_000_000),
      {
        now: NOW,
      },
    );
    assert.equal(report.verdict.status, "pass");
  },
);

test(
  "certificates are outside validity when `now` is far in the future",
  { skip: missing("IMG_0073.HEIC") },
  async () => {
    const { report } = await verifyReferenceImage(
      await loadFixture("IMG_0073.HEIC"),
      { now: "2090-01-01T00:00:00Z" },
    );
    assert.equal(report.verdict.status, "fail");
    assert.ok(
      report.verdict.reasons.some((r) => r.includes("outside validity")),
    );
    // The signature itself is still fine.
    assert.equal(report.signature?.valid, true);
  },
);
