# Changelog

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
