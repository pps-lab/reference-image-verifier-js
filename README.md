# reference-image

Verify the signature of an **Apple Reference Image** (an iPhone photo developed
and signed by Apple's Private Cloud Compute) in Node or the browser, and get a
detailed, JSON-serialisable report of what the file contains.

Zero network access. One runtime dependency
([`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) for
ML-DSA-87); RSA-PSS and SHA-2 use WebCrypto. ESM only, TypeScript types included.

```sh
npm install reference-image
```

## Usage

```ts
import { verifyReferenceImage } from "reference-image";

const bytes = new Uint8Array(await file.arrayBuffer()); // or fs.readFile
const { report, processedJpeg } = await verifyReferenceImage(bytes, {
  fileName: file.name,
});

report.verdict.status; // "pass" | "fail" | "not-reference-image" | "error"
report.verdict.reasons; // human-readable lines
report.hashing?.combinedHash; // the 64-byte value Apple signs, as hex
report.certificates; // signer → issuing CA → root
processedJpeg; // the embedded JPEG that the signature actually covers
```

`verifyReferenceImage` never throws on bad input: unrecognised or malformed
files give `status: "error"`, photos without provenance data give
`"not-reference-image"`.

### Options

| option         | type                 | description                                                                                                                                                   |
| -------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fileName`     | `string`             | Recorded in `report.file.name`.                                                                                                                               |
| `now`          | `Date \| string`     | Reference time for certificate validity (default: now).                                                                                                       |
| `trustAnchors` | `Uint8Array[]` (DER) | Root certificates to trust instead of the built-in public-key pin. With a full certificate the root's validity period and self-signature are checked as well. |

### CLI

```sh
npx reference-image IMG_0073.HEIC
npx reference-image --json IMG_0071.JPG > report.json
npx reference-image --trust-anchor root.cer IMG_0071.JPG
```

Exit status 0 when the verdict is `pass`, 1 otherwise.

## What it checks

1. **Finds the signed object.** A Reference Image is not a signed photo: the
   photo carries a second, smaller JPEG (the "processed image", 3024×4032) and
   that is what Apple signs. In a JPEG export it is split over APP3 segments with
   id `tag:apple.com,2025:chunked_binary_metadata:tag:apple.com,2025:photo:metadata:provenance:processedimage`
   (`u16 seq ‖ u16 total ‖ data`; concatenate, drop a leading 4-byte field). In
   a HEIC it is a `uri ` item (`tag:apple.com,2025:photo:metadata:provenance:processedimage`)
   linked to the primary image with a `cdsc` reference.
2. **Hashes it Apple's way.** With `box3` = the whole APP11 segment whose JUMBF
   box is `62030736-1e8d-403d-b1ce-ef0744a9c392`, and `excluded` = the u32 length
   - the signature DER inside it:

   ```
   P = SHA-512( jpeg[0 : box3.start] )
   S = SHA-512( jpeg[box3.start : box3.end] minus excluded )   # skipped, not zeroed
   C = SHA-512( jpeg[box3.end : EOF] )
   CombinedHash = SHA-512( P ‖ S ‖ C )                        # spec minor >= 1
   ```

3. **Verifies the composite signature** `id-MLDSA87-RSA3072-PSS-SHA512` (IETF
   LAMPS, OID 1.3.6.1.5.5.7.6.52, prefix `CompositeAlgorithmSignatures2025`,
   empty context) over `M' = Prefix ‖ Label ‖ 0x00 ‖ CombinedHash`: ML-DSA-87
   (FIPS 204 pure mode, ctx = label) **and** RSASSA-PSS (SHA-256, MGF1-SHA-256,
   salt 32). Both halves must pass.
4. **Verifies the certificate chain** signer → "Apple Prove ML-DSA RSA Issuing
   CA 1 - G1" → "Apple Prove ML-DSA RSA Root CA G1", each with the same
   composite construction over the TBSCertificate, plus validity dates. The
   root's public key, subject and certificate fingerprint (SHA-256
   `8D7224AE…8A5B`) are pinned in `src/anchors.ts`; the certificate itself is
   not distributed. Pass it through `trustAnchors` if you have it.

**Not checked:** revocation (iOS queries an Apple service with a per-photo
digest), the `ProvoloneProcessedSigning` certificate policy constraints, and
iOS's five-year age limit. The signature binds the hidden processed image
only, not the outer photo's pixels or metadata, and the signer is Apple's
development service, not the capturing iPhone. The report lists these under
`verdict.notChecked` and `verdict.caveats`.

## Lower-level API

Everything the verifier is built from is exported, for projects that need
only a piece of it:

- `verifyComposite({ publicKey, signature, message | digest, ctx? })`,
  `buildMPrime`, `splitPublicKey`, `splitSignature` and the composite constants.
- `parseCertificate`, `parseCertificateList` (X.509 subset).
- `parseJpeg`, `jpegFormat`, `extractChunkedProvenance`, `parseJumbfSegment`, `parseBox`.
- `parseHeif`, `extractHeifProvenance`, `itemBytes`.
- `readExif` (make, model, Exif version and Apple's MakerNote Reference Image flag `0x0063`).
- `APPLE_PROVE_ROOT`, `UUID`, `NOT_CHECKED`, `CAVEATS`, `VERSION`, `ParseError`.

All report types (`Report`, `Verdict`, `CertificateSummary`, …) are exported too.

## Development

```sh
npm install
npm run check   # prettier, eslint, tsc, tests
npm run build   # dist/
```

### Tests

The golden tests need two real iPhone 18 Pro Reference Images and the root
certificate, which are **not** committed. Put them in `test/fixtures/`
(gitignored) or point `REFERENCE_IMAGE_FIXTURES` at a directory containing:

- `IMG_0071.JPG` (JPEG export), `IMG_0073.HEIC`
- `root.cer` (the Apple Prove root CA, DER)

Tests that need a missing fixture are skipped; everything else runs in CI.

### Regenerating the root pin

```sh
node scripts/pin-root.ts path/to/root.cer > src/anchors.ts
```

## License

MIT. Independent research by the
[Privacy Preserving Systems Lab](https://pps-lab.com), University of Toronto;
not affiliated with or endorsed by Apple.
