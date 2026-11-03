// IETF LAMPS composite signature id-MLDSA87-RSA3072-PSS-SHA512 (final
// "CompositeAlgorithmSignatures2025" construction), as used by Apple for the
// Reference Image signature and for every certificate in its chain.
//
//   M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)
//   sig = ML-DSA-87.Sign(M', ctx = Label) || RSASSA-PSS(SHA-256, salt 32)(M')
//
// Apple always uses an empty application context. The caller may pass the
// 64-byte pre-hash directly (that is what CMPhoto's CombinedHash is).

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { der, TAG } from "./asn1.ts";
import { utf8, concat, sha512, ParseError, bufferSource } from "./util.ts";

export const COMPOSITE_OID = "1.3.6.1.5.5.7.6.52";
export const COMPOSITE_NAME = "id-MLDSA87-RSA3072-PSS-SHA512";
export const PREFIX = "CompositeAlgorithmSignatures2025";
export const LABEL = "COMPSIG-MLDSA87-RSA3072-PSS-SHA512";
export const MLDSA87_PK_LEN = 2592;
export const MLDSA87_SIG_LEN = 4627;
export const RSA3072_SIG_LEN = 384;

/** Build the composite message representative M' from a 64-byte pre-hash. */
export function buildMPrime(
  digest: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (digest.length !== 64)
    throw new ParseError("composite: pre-hash must be 64 bytes");
  if (ctx.length > 255) throw new ParseError("composite: ctx too long");
  return concat(
    utf8(PREFIX),
    utf8(LABEL),
    Uint8Array.of(ctx.length),
    ctx,
    digest,
  );
}

export function splitPublicKey(keyBytes: Uint8Array): {
  mldsa: Uint8Array;
  rsaPublicKeyDer: Uint8Array;
} {
  if (keyBytes.length <= MLDSA87_PK_LEN)
    throw new ParseError("composite: public key too short");
  return {
    mldsa: keyBytes.subarray(0, MLDSA87_PK_LEN),
    rsaPublicKeyDer: keyBytes.subarray(MLDSA87_PK_LEN),
  };
}

export function splitSignature(sig: Uint8Array): {
  mldsa: Uint8Array;
  rsa: Uint8Array;
} {
  if (sig.length !== MLDSA87_SIG_LEN + RSA3072_SIG_LEN)
    throw new ParseError(
      `composite: signature is ${sig.length} bytes, expected ${MLDSA87_SIG_LEN + RSA3072_SIG_LEN}`,
    );
  return {
    mldsa: sig.subarray(0, MLDSA87_SIG_LEN),
    rsa: sig.subarray(MLDSA87_SIG_LEN),
  };
}

// WebCrypto only imports RSA keys as SPKI, so wrap the bare RSAPublicKey.
const OID_RSA_ENCRYPTION = Uint8Array.of(
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
);
function rsaSpki(rsaPublicKeyDer: Uint8Array): Uint8Array {
  const alg = der(TAG.SEQUENCE, OID_RSA_ENCRYPTION, Uint8Array.of(0x05, 0x00));
  const bits = der(TAG.BIT_STRING, Uint8Array.of(0), rsaPublicKeyDer);
  return der(TAG.SEQUENCE, alg, bits);
}

async function verifyRsaPss(
  rsaPublicKeyDer: Uint8Array,
  mPrime: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "spki",
    bufferSource(rsaSpki(rsaPublicKeyDer)),
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    bufferSource(sig),
    bufferSource(mPrime),
  );
}

function verifyMlDsa(pk: Uint8Array, mPrime: Uint8Array, sig: Uint8Array) {
  try {
    return ml_dsa87.verify(sig, mPrime, pk, { context: utf8(LABEL) });
  } catch {
    return false;
  }
}

export interface CompositeVerifyInput {
  /** Composite SPKI key bytes: ML-DSA-87 public key || RSAPublicKey DER. */
  publicKey: Uint8Array;
  /** ML-DSA-87 signature || RSA-3072 signature (5011 bytes). */
  signature: Uint8Array;
  /** Message to hash with SHA-512; mutually exclusive with `digest`. */
  message?: Uint8Array;
  /** 64-byte pre-hash (SHA-512 of the message). */
  digest?: Uint8Array;
  /** Application context, empty for everything Apple signs. */
  ctx?: Uint8Array;
}

export interface CompositeVerifyResult {
  mldsa: boolean;
  rsa: boolean;
  /** Both halves verified. */
  valid: boolean;
  mPrime: Uint8Array;
}

/**
 * Verify a composite signature. Pass either `message` (hashed here with
 * SHA-512) or `digest` (the 64-byte pre-hash). A key or signature of the
 * wrong length throws a ParseError; anything else that fails, including an
 * RSA key WebCrypto will not import, returns `valid: false`.
 */
export async function verifyComposite({
  publicKey,
  signature,
  message,
  digest,
  ctx,
}: CompositeVerifyInput): Promise<CompositeVerifyResult> {
  if (!digest && !message)
    throw new ParseError("composite: message or digest is required");
  const pre = digest ?? (await sha512(message!));
  const mPrime = buildMPrime(pre, ctx);
  const key = splitPublicKey(publicKey);
  const sig = splitSignature(signature);
  const mldsa = verifyMlDsa(key.mldsa, mPrime, sig.mldsa);
  const rsa = await verifyRsaPss(key.rsaPublicKeyDer, mPrime, sig.rsa).catch(
    () => false,
  );
  return { mldsa, rsa, valid: mldsa && rsa, mPrime };
}
