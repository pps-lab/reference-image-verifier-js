export {
  verifyReferenceImage,
  UUID,
  NOT_CHECKED,
  CAVEATS,
} from "./provenance.ts";
export type {
  Report,
  Verdict,
  VerdictStatus,
  VerifyOptions,
  VerifyResult,
  FileInfo,
  CarrierInfo,
  ProcessedImage,
  ProcessedSegment,
  Boxes,
  HeaderBox,
  TimestampsBox,
  SignatureBox,
  Hashing,
  HalfResult,
  SignatureInfo,
  SignatureStatus,
  CertificateRole,
  CertificateSummary,
  TrustAnchorSummary,
  ChainEntry,
  ChainInfo,
} from "./report.ts";

export { APPLE_PROVE_ROOT, type PinnedRoot } from "./anchors.ts";
export {
  verifyComposite,
  buildMPrime,
  splitPublicKey,
  splitSignature,
  COMPOSITE_OID,
  COMPOSITE_NAME,
  PREFIX,
  LABEL,
  MLDSA87_PK_LEN,
  MLDSA87_SIG_LEN,
  RSA3072_SIG_LEN,
  type CompositeVerifyInput,
  type CompositeVerifyResult,
} from "./composite.ts";
export {
  parseCertificate,
  parseCertificateList,
  type Certificate,
  type Name,
} from "./x509.ts";
export {
  isJpeg,
  parseJpeg,
  jpegFormat,
  extractChunkedProvenance,
  parseJumbfSegment,
  parseBox,
  CHUNKED_ID,
  type ParsedJpeg,
  type JpegSegment,
  type JpegFormat,
  type ChunkedCarrier,
  type Box,
  type JumbfSegment,
} from "./jpeg.ts";
export {
  isHeif,
  parseHeif,
  extractHeifProvenance,
  itemBytes,
  PROVENANCE_URI,
  type HeifInfo,
  type HeifItem,
  type HeifLocation,
  type HeifCarrier,
} from "./heif.ts";
export { readExif, type ExifSummary } from "./exif.ts";
export { ParseError } from "./util.ts";
export { VERSION } from "./version.ts";
