// The JSON-serialisable report produced by verifyReferenceImage().

import type { ExifSummary } from "./exif.ts";
import type { ChunkedCarrier, JpegFormat } from "./jpeg.ts";
import type { HeifCarrier } from "./heif.ts";

export type VerdictStatus = "pass" | "fail" | "not-reference-image" | "error";

export interface Verdict {
  status: VerdictStatus;
  /** Human-readable reasons for the status (one line each). */
  reasons: string[];
  /** Checks iOS performs that this library does not. */
  notChecked: string[];
  /** What a "pass" does and does not mean. */
  caveats: string[];
}

export interface FileInfo {
  name: string | null;
  size: number;
  container: "jpeg" | "heif" | null;
  width: number | null;
  height: number | null;
  exif: ExifSummary | null;
  /** JPEG containers only. */
  format?: JpegFormat;
  /** HEIF containers only. */
  brand?: string;
  primaryType?: string | null;
  itemCount?: number;
}

export type CarrierInfo =
  Omit<ChunkedCarrier, "data"> | Omit<HeifCarrier, "data">;

export interface ProcessedSegment {
  offset: number;
  length: number;
  marker: number | null;
  name: string;
  detail: string;
  /** Which hash the segment falls into. */
  part: "P" | "S" | "C";
}

export interface ProcessedImage {
  size: number;
  width: number | null;
  height: number | null;
  components: number | null;
  format: JpegFormat;
  trailingBytes: number;
  segments: ProcessedSegment[];
}

export interface HeaderBox {
  offset: number;
  length: number;
  uuid: string;
  instance: number;
  specVersion: string;
  /** UUIDs of the boxes the header indexes. */
  entries: string[];
}

export interface TimestampsBox {
  offset: number;
  length: number;
  uuid: string;
  instance: number;
  innerUuid: string | undefined;
  unix: number[];
  iso: string[];
}

export interface SignatureBox {
  offset: number;
  length: number;
  uuid: string;
  instance: number;
  innerUuid: string | undefined;
  innerOffset: number;
  innerLength: number;
  sigLenOffset: number;
  sigDerOffset: number;
  sigDerLength: number;
  bundleLenOffset: number;
  bundleOffset: number;
  bundleLength: number;
  trailerOffset: number;
  trailerLength: number;
  trailerHex: string;
  developedAtUnix: number | null;
  developedAt: string | null;
}

export interface Boxes {
  header: HeaderBox | null;
  timestamps: TimestampsBox | null;
  signature: SignatureBox;
  all: {
    offset: number;
    length: number;
    uuid: string | undefined;
    instance: number;
    sequence: number;
  }[];
}

export interface Hashing {
  algorithm: "SHA-512";
  specVersion: string;
  order: "P || S || C" | "S || C";
  ranges: {
    preamble: [number, number];
    signatureParameters: [number, number];
    excluded: [number, number];
    content: [number, number];
  };
  preambleHash: string;
  signatureParametersHash: string;
  contentHash: string;
  combinedHash: string;
  mPrime: {
    prefix: string;
    label: string;
    ctxLength: number;
    ctx: string;
    digest: string;
    totalBytes: number;
  };
}

export interface HalfResult {
  name: string;
  length: number;
  valid: boolean;
}

export interface SignatureInfo {
  structureVersion: string;
  bundleVersion: string;
  algorithmOid: string;
  algorithm: string;
  length: number;
  mldsa: HalfResult;
  rsa: HalfResult;
  valid: boolean;
  signerSerial: string;
  mPrimeHex: string | null;
}

export type CertificateRole =
  "signer" | "issuing-ca" | "intermediate-ca" | "root";

export interface SignatureStatus {
  mldsa: boolean;
  rsa: boolean;
  valid: boolean;
}

/** A certificate that was parsed: either from the file, or a trust anchor passed by the caller. */
export interface CertificateSummary {
  role: CertificateRole;
  subject: string;
  subjectCN: string | null;
  issuer: string;
  issuerCN: string | null;
  serial: string;
  notBefore: string;
  notAfter: string;
  /** Uppercase hex SHA-256 of the DER. */
  sha256: string;
  algorithmOid: string;
  algorithm: string;
  derLength: number;
  embeddedInFile: boolean;
  /** Subject CN of the certificate whose key verified this one, or null. */
  verifiedBy: string | null;
  signature: SignatureStatus;
  withinValidity: boolean;
  isTrustAnchor: boolean;
}

/** The pinned root: only its subject, fingerprint and public key are known. */
export interface TrustAnchorSummary {
  role: "root";
  subject: string;
  subjectCN: string;
  sha256: string;
  algorithmOid: string;
  algorithm: string;
  embeddedInFile: false;
  isTrustAnchor: true;
}

export type ChainEntry = CertificateSummary | TrustAnchorSummary;

export interface ChainInfo {
  valid: boolean;
  /** The top certificate in the file is issued and signed by a trust anchor. */
  reachesTrustAnchor: boolean;
  /** Number of entries including the anchor. */
  length: number;
  errors: string[];
  /** Whether the developed-at trailer time falls inside the signer's validity. */
  developedWithinSignerValidity: boolean | null;
}

export interface Report {
  toolVersion: string;
  analyzedAt: string;
  file: FileInfo;
  carrier: CarrierInfo | null;
  processed: ProcessedImage | null;
  boxes: Boxes | null;
  hashing: Hashing | null;
  signature: SignatureInfo | null;
  certificates: ChainEntry[];
  chain: ChainInfo | null;
  verdict: Verdict;
  error?: { name: string; message: string };
}

export interface VerifyOptions {
  /** Recorded in the report; not used for anything else. */
  fileName?: string;
  /** Reference time for certificate validity; defaults to now. */
  now?: Date | string;
  /**
   * Root certificates (DER) to trust instead of the built-in public-key pin.
   * With a full certificate the root's validity period and self-signature are
   * checked too, and it is reported as a CertificateSummary.
   */
  trustAnchors?: Uint8Array[];
}

export interface VerifyResult {
  report: Report;
  /** The embedded processed JPEG (the signed bytes), when one was found. */
  processedJpeg: Uint8Array | null;
}
