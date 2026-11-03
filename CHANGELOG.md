# Changelog

## 0.2.0

- The Apple Prove root certificate now ships in the package
  (`APPLE_PROVE_ROOT.der`), replacing the public-key pin. The root's validity
  and self-signature are now always checked.
- Breaking: `TrustAnchorSummary` is removed; the root is reported as a
  `CertificateSummary`. `ChainEntry` remains as an alias.
- `scripts/pin-root.ts` is renamed to `scripts/embed-root.ts`.
- When a photo has no provenance data, a second reason gives the likely cause
  from its Exif: no Exif, non-Apple make, missing or non-Apple MakerNote, or
  the Reference Image flag (0x0063) missing, not 8, or 8 with the data
  stripped. New `ExifSummary.makerNote` field.
- Parse errors name the part of the file that failed. Empty, PNG, GIF, WebP,
  PDF and TIFF files are identified.

## 0.1.0

Initial release.

- `verifyReferenceImage()`: extracts the signed processed image from an iPhone
  JPEG export or HEIC, recomputes Apple's SHA-512 hash tree, verifies the
  ML-DSA-87 + RSA-3072-PSS composite signature and the certificate chain, and
  returns a JSON-serialisable report.
- Built-in public-key pin of the Apple Prove root CA; `trustAnchors` option to
  supply root certificates instead.
- Lower-level exports: composite signature verification, X.509, JPEG/JUMBF and
  HEIF parsers, Exif reader.
- `reference-image` CLI.
