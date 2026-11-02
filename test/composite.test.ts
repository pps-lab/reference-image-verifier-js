import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  APPLE_PROVE_ROOT,
  buildMPrime,
  splitPublicKey,
  splitSignature,
  parseCertificate,
  verifyComposite,
  COMPOSITE_OID,
  MLDSA87_PK_LEN,
  ParseError,
  VERSION,
} from "../src/index.ts";
import { hasFixture, loadFixture } from "./fixtures.ts";

test("VERSION matches package.json", async () => {
  const pkg = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version: string };
  assert.equal(VERSION, pkg.version);
});

test("pinned root: key splits into ML-DSA-87 || RSAPublicKey", () => {
  const { mldsa, rsaPublicKeyDer } = splitPublicKey(APPLE_PROVE_ROOT.publicKey);
  assert.equal(mldsa.length, MLDSA87_PK_LEN);
  // RSAPublicKey ::= SEQUENCE { modulus INTEGER (3072 bit), publicExponent INTEGER }
  assert.deepEqual([...rsaPublicKeyDer.subarray(0, 2)], [0x30, 0x82]);
  assert.equal(APPLE_PROVE_ROOT.algorithmOid, COMPOSITE_OID);
  assert.match(APPLE_PROVE_ROOT.certSha256, /^[0-9A-F]{64}$/);
  assert.equal(APPLE_PROVE_ROOT.subjectCN, "Apple Prove ML-DSA RSA Root CA G1");
});

test("buildMPrime: prefix, label, empty ctx, digest", () => {
  const digest = new Uint8Array(64).fill(7);
  const m = buildMPrime(digest);
  assert.equal(m.length, 131);
  const text = new TextDecoder().decode(m.subarray(0, 66));
  assert.equal(
    text,
    "CompositeAlgorithmSignatures2025COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
  );
  assert.equal(m[66], 0);
  assert.deepEqual(m.subarray(67), digest);
  assert.throws(() => buildMPrime(new Uint8Array(32)), ParseError);
  assert.throws(() => buildMPrime(digest, new Uint8Array(256)), ParseError);
});

test("splitSignature rejects wrong lengths", () => {
  assert.throws(() => splitSignature(new Uint8Array(5010)), ParseError);
  const s = splitSignature(new Uint8Array(5011));
  assert.deepEqual([s.mldsa.length, s.rsa.length], [4627, 384]);
});

test("verifyComposite: garbage signature of the right length fails both halves", async () => {
  const r = await verifyComposite({
    publicKey: APPLE_PROVE_ROOT.publicKey,
    signature: new Uint8Array(5011),
    message: new Uint8Array([1, 2, 3]),
  });
  assert.deepEqual([r.mldsa, r.rsa, r.valid], [false, false, false]);
});

const noRoot = hasFixture("root.cer") ? false : "fixture root.cer not present";

test(
  "root certificate matches the pin and is self-signed",
  { skip: noRoot },
  async () => {
    const root = await parseCertificate(await loadFixture("root.cer"));
    assert.equal(root.fingerprintSha256, APPLE_PROVE_ROOT.certSha256);
    assert.equal(root.subject.dn, APPLE_PROVE_ROOT.subject);
    assert.equal(root.subject.cn, APPLE_PROVE_ROOT.subjectCN);
    assert.deepEqual(root.spki.keyBytes, APPLE_PROVE_ROOT.publicKey);
    assert.equal(root.algorithmOid, COMPOSITE_OID);
    assert.ok(root.selfIssued);
    const r = await verifyComposite({
      publicKey: root.spki.keyBytes,
      signature: root.signature,
      message: root.tbs,
    });
    assert.deepEqual(
      { mldsa: r.mldsa, rsa: r.rsa },
      { mldsa: true, rsa: true },
    );
  },
);

test("a flipped TBS byte breaks both halves", { skip: noRoot }, async () => {
  const root = await parseCertificate(await loadFixture("root.cer"));
  const tbs = new Uint8Array(root.tbs);
  tbs[40]! ^= 1;
  const r = await verifyComposite({
    publicKey: root.spki.keyBytes,
    signature: root.signature,
    message: tbs,
  });
  assert.deepEqual(
    { mldsa: r.mldsa, rsa: r.rsa },
    { mldsa: false, rsa: false },
  );
});
