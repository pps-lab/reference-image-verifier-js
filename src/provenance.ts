// The Apple Reference Image verification recipe:
//
//   box3     = the whole APP11 segment whose JUMBF box is 62030736-…
//   excluded = [sig_off - 4, sig_off + len(sigDER))   (u32 length + DER)
//   P = SHA-512(jpeg[0 : box3.start])
//   S = SHA-512(jpeg[box3.start : box3.end] minus excluded)
//   C = SHA-512(jpeg[box3.end : EOF])
//   CombinedHash = SHA-512(P || S || C)          (spec minor >= 1)
//   composite verify with pre-hash = CombinedHash, ctx empty
//
// Produces a JSON-serialisable `report`.

import {
  isJpeg,
  parseJpeg,
  segmentId,
  extractChunkedProvenance,
  parseJumbfSegment,
  parseBox,
  outerJpegInfo,
  jpegFormat,
  type JpegSegment,
  type JumbfSegment,
} from "./jpeg.ts";
import {
  isHeif,
  parseHeif,
  extractHeifProvenance,
  outerHeifInfo,
} from "./heif.ts";
import {
  TAG,
  readTLV,
  children,
  bytesOf,
  expect,
  oid,
  smallInt,
} from "./asn1.ts";
import {
  parseCertificate,
  parseCertificateList,
  type Certificate,
} from "./x509.ts";
import {
  verifyComposite,
  COMPOSITE_OID,
  COMPOSITE_NAME,
  PREFIX,
  LABEL,
  MLDSA87_SIG_LEN,
  RSA3072_SIG_LEN,
} from "./composite.ts";
import { APPLE_PROVE_ROOT } from "./anchors.ts";
import type { ExifSummary } from "./exif.ts";
import { VERSION } from "./version.ts";
import {
  ParseError,
  hex,
  sha512,
  u16,
  u32,
  u64,
  ascii,
  uuidString,
  equalBytes,
} from "./util.ts";
import type {
  CertificateRole,
  CertificateSummary,
  HeaderBox,
  Report,
  SignatureStatus,
  TimestampsBox,
  VerifyOptions,
  VerifyResult,
} from "./report.ts";

/** JUMBF box UUIDs used by Apple's provenance boxes. */
export const UUID = {
  header: "3c32166f-ae98-414c-a0b1-da48dc9cd85e",
  timestamps: "1c4f261e-6184-4f47-bada-217c1c41d242",
  mutable: "62030736-1e8d-403d-b1ce-ef0744a9c392",
  timestampsInner: "3cd5877f-7041-44de-b48c-6fc34ae3ee6a",
  signatureInner: "f3c1115f-eee7-401b-9939-9749f4467d66",
} as const;

export const NOT_CHECKED: readonly string[] = [
  "Revocation: iOS checks a per-photo digest (FileContentsPartialDigest) against Apple's revocation service. This library makes no network requests.",
  "Certificate policy: the SecTrust policy ProvoloneProcessedSigning (EKUs, policy OIDs) is not reproduced.",
  "Age limit: iOS rejects provenance for photos developed more than five years ago.",
];
export const CAVEATS: readonly string[] = [
  "The signature covers the embedded 'processed image' JPEG, not the pixels or metadata of the outer photo you see.",
  "The signer is Apple's development service (one key for many photos), not your iPhone.",
  "Recipe reverse-engineered from iOS 27.0.1 CMPhoto and tested on iPhone 18 Pro photos with spec version 1.3.",
];

const SOF_NAMES: Record<string, string> = {
  SOF0: "baseline DCT",
  SOF1: "extended sequential DCT",
  SOF2: "progressive DCT",
};

function segmentDetail(bytes: Uint8Array, s: JpegSegment): string {
  switch (s.name) {
    case "APP0":
      return ascii(bytes, s.payloadStart, 4) === "JFIF"
        ? "JFIF header"
        : "APP0";
    case "APP1":
      return segmentId(bytes, s) === "Exif"
        ? "Exif metadata"
        : segmentId(bytes, s);
    case "APP2":
      return segmentId(bytes, s) === "ICC_PROFILE"
        ? "ICC colour profile"
        : segmentId(bytes, s);
    case "APP10":
      return ascii(bytes, s.payloadStart, 4) === "AROT"
        ? "Apple AROT (scan index)"
        : "APP10";
    case "SOF0":
    case "SOF1":
    case "SOF2":
      return `Frame header ${u16(bytes, s.payloadStart + 3)}×${u16(bytes, s.payloadStart + 1)}, ${SOF_NAMES[s.name]}`;
    case "DHT":
      return "Huffman tables";
    case "DQT":
      return "Quantisation tables";
    case "DRI":
      return "Restart interval";
    case "SOS":
      return "Start of scan";
    case "scan":
      return "Entropy-coded pixel data";
    case "SOI":
      return "Start of image";
    case "EOI":
      return "End of image";
    default:
      return s.name;
  }
}

function parseSignatureDer(bytes: Uint8Array, off: number, len: number) {
  const seq = expect(readTLV(bytes, off), TAG.SEQUENCE, "SignatureData");
  if (seq.end !== off + len)
    throw new ParseError("signature DER length mismatch");
  const [ver, oct] = children(bytes, seq);
  if (!ver || !oct) throw new ParseError("SignatureData: missing fields");
  const [major, minor] = children(bytes, ver).map((n) => smallInt(bytes, n));
  expect(oct, TAG.OCTET_STRING, "signature OCTET STRING");
  return {
    structureVersion: `${major}.${minor}`,
    signature: bytesOf(bytes, oct),
  };
}

async function parseBundleDer(bytes: Uint8Array, off: number, len: number) {
  const seq = expect(readTLV(bytes, off), TAG.SEQUENCE, "SignatureParameters");
  if (seq.end !== off + len) throw new ParseError("bundle DER length mismatch");
  const [ver, alg, list] = children(bytes, seq);
  if (!ver || !alg || !list)
    throw new ParseError("SignatureParameters: missing fields");
  const [major, minor] = children(bytes, ver).map((n) => smallInt(bytes, n));
  const algOidNode = children(bytes, alg)[0];
  if (!algOidNode) throw new ParseError("SignatureParameters: missing OID");
  return {
    structureVersion: `${major}.${minor}`,
    algorithmOid: oid(bytes, algOidNode),
    certificates: await parseCertificateList(bytes, list),
  };
}

const algorithmName = (o: string) => (o === COMPOSITE_OID ? COMPOSITE_NAME : o);

function certSummary(
  c: Certificate,
  role: CertificateRole,
  extra: {
    embeddedInFile: boolean;
    verifiedBy: string | null;
    signature: SignatureStatus;
    withinValidity: boolean;
    isTrustAnchor: boolean;
  },
): CertificateSummary {
  return {
    role,
    subject: c.subject.dn,
    subjectCN: c.subject.cn,
    issuer: c.issuer.dn,
    issuerCN: c.issuer.cn,
    serial: c.serial,
    notBefore: c.notBefore.toISOString(),
    notAfter: c.notAfter.toISOString(),
    sha256: c.fingerprintSha256,
    algorithmOid: c.algorithmOid,
    algorithm: algorithmName(c.algorithmOid),
    derLength: c.der.length,
    ...extra,
  };
}

async function loadAnchors(
  ders: Uint8Array[] | undefined,
): Promise<Certificate[]> {
  if (!ders) {
    const root = await parseCertificate(APPLE_PROVE_ROOT.der);
    if (root.fingerprintSha256 !== APPLE_PROVE_ROOT.certSha256)
      throw new Error(
        "built-in root certificate does not match its fingerprint",
      );
    return [root];
  }
  if (!ders.length) throw new ParseError("trustAnchors must not be empty");
  const out: Certificate[] = [];
  for (const der of ders) out.push(await parseCertificate(der));
  return out;
}

const NO_SIG: SignatureStatus = { mldsa: false, rsa: false, valid: false };

async function verifyCertWith(
  issuerKey: Uint8Array,
  issuerKeyOid: string,
  c: Certificate,
): Promise<SignatureStatus> {
  if (issuerKeyOid !== COMPOSITE_OID || c.algorithmOid !== COMPOSITE_OID)
    return NO_SIG;
  try {
    const r = await verifyComposite({
      publicKey: issuerKey,
      signature: c.signature,
      message: c.tbs,
    });
    return { mldsa: r.mldsa, rsa: r.rsa, valid: r.valid };
  } catch (e) {
    if (e instanceof ParseError) return NO_SIG;
    throw e;
  }
}

async function anchorSummary(
  c: Certificate,
  now: Date,
): Promise<CertificateSummary> {
  return certSummary(c, "root", {
    embeddedInFile: false,
    verifiedBy: c.subject.cn,
    signature: await verifyCertWith(c.spki.keyBytes, c.spki.algorithmOid, c),
    withinValidity: c.notBefore <= now && now <= c.notAfter,
    isTrustAnchor: true,
  });
}

/** Prefix ParseErrors thrown by `fn` with `what`. */
async function inStep<T>(what: string, fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ParseError)
      throw new ParseError(`${what}: ${e.message}`, { cause: e });
    throw e;
  }
}

function unrecognisedFile(b: Uint8Array): string {
  const sig = (s: string, at = 0) => ascii(b, at, s.length) === s;
  if (!b.length) return "The file is empty.";
  const kind = sig("\x89PNG")
    ? "a PNG image"
    : sig("GIF8")
      ? "a GIF image"
      : sig("RIFF") && sig("WEBP", 8)
        ? "a WebP image"
        : sig("%PDF")
          ? "a PDF document"
          : sig("II*\0") || sig("MM\0*")
            ? "a TIFF or raw image"
            : null;
  return kind
    ? `This is ${kind}, not a JPEG or HEIC.`
    : "Unrecognised file: expected a JPEG or HEIC/HEIF image.";
}

/** Guess from the outer photo's (unsigned) Exif why it has no provenance data. */
function missingProvenanceHint(exif: ExifSummary | null): string {
  if (!exif)
    return "No readable Exif metadata: the photo was likely re-encoded or had its metadata stripped.";
  if (exif.make !== "Apple")
    return exif.make
      ? `Camera make is "${exif.make}", not Apple.`
      : "No camera make in the Exif metadata.";
  if (exif.makerNote === null)
    return "Exif has no MakerNote (0x927C): the metadata was likely rewritten by an editor or export.";
  if (exif.makerNote === "other")
    return "MakerNote is not Apple's: the metadata was likely rewritten by an editor or export.";
  if (exif.appleReferenceFlag === 8)
    return "Apple MakerNote flags a developed Reference Image (0x0063 = 8), but the signed data is missing: it was likely stripped on export or sharing.";
  if (exif.appleReferenceFlag === null)
    return "Apple MakerNote has no Reference Image flag (0x0063).";
  return `Apple MakerNote Reference Image flag (0x0063) is ${exif.appleReferenceFlag}, not 8.`;
}

/**
 * Verify one photo file (JPEG export or HEIC) as an Apple Reference Image.
 *
 * Never rejects on bad file input: malformed bytes yield
 * `report.verdict.status === "error"` and a photo without provenance data
 * yields `"not-reference-image"`. An invalid `now` is a programmer error and
 * throws a RangeError.
 */
export async function verifyReferenceImage(
  bytes: Uint8Array,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  const now = opts.now ? new Date(opts.now) : new Date();
  if (Number.isNaN(now.getTime())) throw new RangeError("invalid `now`");
  const report: Report = {
    toolVersion: VERSION,
    analyzedAt: now.toISOString(),
    file: {
      name: opts.fileName ?? null,
      size: bytes.length,
      container: null,
      width: null,
      height: null,
      exif: null,
    },
    carrier: null,
    processed: null,
    boxes: null,
    hashing: null,
    signature: null,
    certificates: [],
    chain: null,
    verdict: {
      status: "error",
      reasons: [],
    },
  };
  let processedJpeg: Uint8Array | null = null;
  try {
    const anchors = await loadAnchors(opts.trustAnchors);

    let carrier;
    if (isJpeg(bytes)) {
      report.file.container = "jpeg";
      const outer = await inStep("The JPEG file is malformed", () =>
        parseJpeg(bytes),
      );
      Object.assign(report.file, outerJpegInfo(bytes, outer));
      carrier = await inStep("The provenance data is damaged", () =>
        extractChunkedProvenance(bytes, outer),
      );
    } else if (isHeif(bytes)) {
      report.file.container = "heif";
      const info = await inStep("The HEIC file is malformed", () =>
        parseHeif(bytes),
      );
      Object.assign(report.file, outerHeifInfo(bytes, info));
      carrier = await inStep("The provenance data is damaged", () =>
        extractHeifProvenance(bytes, info),
      );
    } else {
      throw new ParseError(unrecognisedFile(bytes));
    }
    if (!carrier) {
      report.verdict.status = "not-reference-image";
      report.verdict.reasons.push(
        report.file.container === "jpeg"
          ? "No Apple provenance APP3 chunks found. This JPEG does not carry a Reference Image."
          : "No provenance item (tag:apple.com,2025:photo:metadata:provenance:processedimage) found. This HEIC does not carry a Reference Image.",
        missingProvenanceHint(report.file.exif),
      );
      return { report, processedJpeg: null };
    }
    const { data, ...carrierFacts } = carrier;
    report.carrier = carrierFacts;
    processedJpeg = data;

    const { pj, jumbf } = await inStep(
      "The embedded processed image is malformed",
      () => {
        const pj = parseJpeg(data);
        const jumbf: JumbfSegment[] = [];
        for (const s of pj.segments)
          if (s.marker === 0xeb) {
            const j = parseJumbfSegment(data, s);
            if (j) jumbf.push(j);
          }
        return { pj, jumbf };
      },
    );
    const byUuid = (u: string) => jumbf.find((j) => j.box.uuid === u);
    const hdr = byUuid(UUID.header),
      ts = byUuid(UUID.timestamps),
      mut = byUuid(UUID.mutable);
    if (!mut)
      throw new ParseError(
        "Provenance image found, but its signature box (JUMBF 62030736-…) is missing.",
      );

    // header box: 00000000 | u16 major | u16 minor | u8 count | count × ("uuid" + 16 bytes)
    let specVersion: [number, number] = [1, 3];
    let headerBox: HeaderBox | null = null;
    if (hdr) {
      const c = hdr.box.contentStart;
      if (c + 9 > hdr.box.contentEnd)
        throw new ParseError("Provenance header box too short");
      specVersion = [u16(data, c + 4), u16(data, c + 6)];
      const n = data[c + 8]!;
      const entries: string[] = [];
      for (
        let k = 0, o = c + 9;
        k < n && o + 20 <= hdr.box.contentEnd;
        k++, o += 20
      )
        entries.push(uuidString(data, o + 4));
      headerBox = {
        offset: hdr.segment.offset,
        length: hdr.segment.length,
        uuid: hdr.box.uuid ?? "",
        instance: hdr.instance,
        specVersion: specVersion.join("."),
        entries,
      };
    }
    // timestamps box: inner uuid box | 00000000 | 3 × u64 seconds
    let timestampsBox: TimestampsBox | null = null;
    if (ts) {
      const inner = parseBox(data, ts.box.contentStart, ts.box.contentEnd);
      const c = inner.contentStart + 4;
      const values: number[] = [];
      for (let o = c; o + 8 <= inner.contentEnd; o += 8)
        values.push(u64(data, o));
      timestampsBox = {
        offset: ts.segment.offset,
        length: ts.segment.length,
        uuid: ts.box.uuid ?? "",
        instance: ts.instance,
        innerUuid: inner.uuid,
        unix: values,
        iso: values.map((v) => new Date(v * 1000).toISOString()),
      };
    }
    // signature box: inner uuid box | 00000000 | u32 sigLen | SignatureData DER
    //                | u32 bundleLen | SignatureParameters DER | trailer
    const inner = parseBox(data, mut.box.contentStart, mut.box.contentEnd);
    if (inner.uuid !== UUID.signatureInner)
      throw new ParseError(
        `Unexpected inner box ${inner.uuid ?? inner.type} in signature box`,
      );
    const b = inner.offset;
    const sigLenOffset = b + 28;
    if (sigLenOffset + 4 > inner.contentEnd)
      throw new ParseError("Signature box too short");
    const sigLen = u32(data, sigLenOffset);
    const sigDerOffset = sigLenOffset + 4;
    const bundleLenOffset = sigDerOffset + sigLen;
    if (bundleLenOffset + 4 > inner.contentEnd)
      throw new ParseError("Signature box lengths exceed the box");
    const bundleLen = u32(data, bundleLenOffset);
    const bundleOffset = bundleLenOffset + 4;
    const trailerOffset = bundleOffset + bundleLen;
    if (trailerOffset > inner.contentEnd)
      throw new ParseError("Signature box lengths exceed the box");
    const trailerLength = inner.contentEnd - trailerOffset;
    const developedAt =
      trailerLength >= 4 ? u32(data, inner.contentEnd - 4) : null;
    const box3 = { start: mut.segment.offset, end: mut.segment.payloadEnd };
    const excluded = { start: sigLenOffset, end: sigDerOffset + sigLen };
    report.boxes = {
      header: headerBox,
      timestamps: timestampsBox,
      signature: {
        offset: box3.start,
        length: box3.end - box3.start,
        uuid: mut.box.uuid ?? "",
        instance: mut.instance,
        innerUuid: inner.uuid,
        innerOffset: inner.offset,
        innerLength: inner.size,
        sigLenOffset,
        sigDerOffset,
        sigDerLength: sigLen,
        bundleLenOffset,
        bundleOffset,
        bundleLength: bundleLen,
        trailerOffset,
        trailerLength,
        trailerHex: hex(data.subarray(trailerOffset, inner.contentEnd), " "),
        developedAtUnix: developedAt,
        developedAt:
          developedAt !== null
            ? new Date(developedAt * 1000).toISOString()
            : null,
      },
      all: jumbf.map((j) => ({
        offset: j.segment.offset,
        length: j.segment.length,
        uuid: j.box.uuid,
        instance: j.instance,
        sequence: j.sequence,
      })),
    };
    const part = (s: JpegSegment): "P" | "S" | "C" =>
      s.offset < box3.start ? "P" : s.offset < box3.end ? "S" : "C";
    report.processed = {
      size: data.length,
      width: pj.width,
      height: pj.height,
      components: pj.components,
      format: jpegFormat(data, pj),
      trailingBytes: pj.trailingBytes,
      segments: pj.segments.map((s) => ({
        offset: s.offset,
        length: s.length,
        marker: s.marker,
        name: s.name,
        detail:
          s.marker === 0xeb
            ? `JUMBF box ${jumbf.find((j) => j.segment === s)?.box.uuid ?? "?"}`
            : segmentDetail(data, s),
        part: part(s),
      })),
    };

    const minor = specVersion[1];
    const P = await sha512(data.subarray(0, box3.start));
    const S = await sha512(
      data.subarray(box3.start, excluded.start),
      data.subarray(excluded.end, box3.end),
    );
    const C = await sha512(data.subarray(box3.end));
    const combined = minor >= 1 ? await sha512(P, S, C) : await sha512(S, C);
    report.hashing = {
      algorithm: "SHA-512",
      specVersion: specVersion.join("."),
      order: minor >= 1 ? "P || S || C" : "S || C",
      ranges: {
        preamble: [0, box3.start],
        signatureParameters: [box3.start, box3.end],
        excluded: [excluded.start, excluded.end],
        content: [box3.end, data.length],
      },
      preambleHash: hex(P),
      signatureParametersHash: hex(S),
      contentHash: hex(C),
      combinedHash: hex(combined),
      mPrime: {
        prefix: PREFIX,
        label: LABEL,
        ctxLength: 0,
        ctx: "",
        digest: hex(combined),
        totalBytes: PREFIX.length + LABEL.length + 1 + combined.length,
      },
    };

    const sigDer = await inStep("The signature is malformed", () =>
      parseSignatureDer(data, sigDerOffset, sigLen),
    );
    const bundle = await inStep("The certificate bundle is malformed", () =>
      parseBundleDer(data, bundleOffset, bundleLen),
    );

    // Order bundle certs: the leaf is the one nobody else names as issuer.
    const certs = bundle.certificates;
    const anchorFor = (c: Certificate): Certificate | undefined =>
      anchors.find((a) => equalBytes(a.subject.raw, c.issuer.raw));
    const issuedBy = (c: Certificate): Certificate | undefined =>
      certs.find((x) => x !== c && equalBytes(x.subject.raw, c.issuer.raw));
    const leaf =
      certs.find(
        (c) =>
          !certs.some(
            (x) => x !== c && equalBytes(x.issuer.raw, c.subject.raw),
          ),
      ) ?? certs[0]!;
    const ordered: Certificate[] = [leaf];
    for (let c = issuedBy(leaf); c && !ordered.includes(c); c = issuedBy(c))
      ordered.push(c);
    const top = ordered[ordered.length - 1]!;
    const matchedAnchor = anchorFor(top);
    const chainReachesAnchor = matchedAnchor !== undefined;

    let imageSig: SignatureStatus & { mPrime?: Uint8Array } = NO_SIG;
    if (
      sigDer.structureVersion === "1.0" &&
      leaf.spki.algorithmOid === COMPOSITE_OID
    ) {
      try {
        imageSig = await verifyComposite({
          publicKey: leaf.spki.keyBytes,
          signature: sigDer.signature,
          digest: combined,
        });
      } catch (e) {
        if (!(e instanceof ParseError)) throw e;
      }
    }
    report.signature = {
      structureVersion: sigDer.structureVersion,
      bundleVersion: bundle.structureVersion,
      algorithmOid: bundle.algorithmOid,
      algorithm: algorithmName(bundle.algorithmOid),
      length: sigDer.signature.length,
      mldsa: {
        name: "ML-DSA-87",
        length: MLDSA87_SIG_LEN,
        valid: imageSig.mldsa,
      },
      rsa: {
        name: "RSA-3072 PSS (SHA-256, salt 32)",
        length: RSA3072_SIG_LEN,
        valid: imageSig.rsa,
      },
      valid: imageSig.valid,
      signerSerial: leaf.serial,
      mPrimeHex: imageSig.mPrime ? hex(imageSig.mPrime) : null,
    };

    const roles: CertificateRole[] = ["signer", "issuing-ca"];
    const chainErrors: string[] = [];
    for (let k = 0; k < ordered.length; k++) {
      const c = ordered[k]!;
      const issuerCert = issuedBy(c);
      const issuerAnchor = issuerCert ? undefined : anchorFor(c);
      let sig = NO_SIG;
      let verifiedBy: string | null = null;
      if (issuerCert) {
        sig = await verifyCertWith(
          issuerCert.spki.keyBytes,
          issuerCert.spki.algorithmOid,
          c,
        );
        verifiedBy = issuerCert.subject.cn;
      } else if (issuerAnchor) {
        sig = await verifyCertWith(
          issuerAnchor.spki.keyBytes,
          issuerAnchor.spki.algorithmOid,
          c,
        );
        verifiedBy = issuerAnchor.subject.cn;
      }
      const withinValidity = c.notBefore <= now && now <= c.notAfter;
      const cn = c.subject.cn ?? c.subject.dn;
      if (!issuerCert && !issuerAnchor)
        chainErrors.push(
          `${cn}: issuer "${c.issuer.cn ?? c.issuer.dn}" not found in the file or the trust anchors`,
        );
      if (!sig.valid)
        chainErrors.push(
          `${cn}: certificate signature invalid (ML-DSA ${sig.mldsa ? "ok" : "fail"}, RSA ${sig.rsa ? "ok" : "fail"})`,
        );
      if (!withinValidity) chainErrors.push(`${cn}: outside validity period`);
      report.certificates.push(
        certSummary(c, roles[k] ?? "intermediate-ca", {
          embeddedInFile: true,
          verifiedBy,
          signature: sig,
          withinValidity,
          isTrustAnchor: false,
        }),
      );
    }
    const reported = matchedAnchor ?? anchors[0]!;
    const anchorEntry = await anchorSummary(reported, now);
    if (!anchorEntry.withinValidity)
      chainErrors.push("Root: outside validity period");
    if (!anchorEntry.signature.valid)
      chainErrors.push("Root: self-signature invalid");
    report.certificates.push(anchorEntry);
    if (!chainReachesAnchor)
      chainErrors.push("Chain does not end at a trusted root");
    const developedWithinSigner =
      developedAt !== null
        ? leaf.notBefore.getTime() / 1000 <= developedAt &&
          developedAt <= leaf.notAfter.getTime() / 1000
        : null;
    report.chain = {
      valid: chainErrors.length === 0,
      reachesTrustAnchor: chainReachesAnchor,
      length: ordered.length + 1,
      errors: chainErrors,
      developedWithinSignerValidity: developedWithinSigner,
    };

    const reasons: string[] = [];
    if (!imageSig.valid)
      reasons.push(
        `Image signature invalid (ML-DSA-87 ${imageSig.mldsa ? "ok" : "FAIL"}, RSA-3072-PSS ${imageSig.rsa ? "ok" : "FAIL"}).`,
      );
    reasons.push(...chainErrors);
    if (carrier.kind === "heif-item" && !carrier.describesPrimary)
      reasons.push(
        "Provenance item is not linked (cdsc) to the primary image.",
      );
    report.verdict.status = reasons.length ? "fail" : "pass";
    report.verdict.reasons = reasons.length
      ? reasons
      : [
          "Both halves of the composite signature verify, and the certificate chain ends at the Apple Prove root.",
        ];
  } catch (e) {
    const err = e instanceof Error ? e : new Error(String(e));
    report.verdict.status = "error";
    report.verdict.reasons = [
      err instanceof ParseError
        ? err.message
        : `Unexpected error: ${err.message}`,
    ];
    report.error = { name: err.name, message: err.message };
  }
  return { report, processedJpeg };
}
