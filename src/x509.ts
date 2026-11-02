// X.509 parsing limited to what the Reference Image chain needs. Signature
// algorithms other than the composite are reported but not verified.

import {
  TAG,
  readTLV,
  children,
  bytesOf,
  rawOf,
  expect,
  oid,
  integerHex,
  bitString,
  time,
  type TLV,
} from "./asn1.ts";
import { ParseError, hex, sha256, equalBytes } from "./util.ts";

const OID_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
};

export interface Name {
  cn: string | null;
  /** e.g. "CN=Apple Prove ML-DSA RSA Signer, O=Apple Inc., C=US" */
  dn: string;
  /** DER of the whole Name, for exact issuer/subject matching. */
  raw: Uint8Array;
}

function parseName(buf: Uint8Array, node: TLV): Name {
  expect(node, TAG.SEQUENCE, "Name");
  const parts: string[] = [];
  let cn: string | null = null;
  for (const rdn of children(buf, node)) {
    for (const atv of children(buf, rdn)) {
      const [o, v] = children(buf, atv);
      if (!o || !v)
        throw new ParseError("DER: malformed AttributeTypeAndValue");
      const key = oid(buf, o);
      const value = new TextDecoder().decode(bytesOf(buf, v));
      parts.push(`${OID_NAMES[key] ?? key}=${value}`);
      if (key === "2.5.4.3") cn = value;
    }
  }
  return { cn, dn: parts.join(", "), raw: rawOf(buf, node) };
}

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  serial: string;
  subject: Name;
  issuer: Name;
  notBefore: Date;
  notAfter: Date;
  /** Outer signatureAlgorithm OID. */
  algorithmOid: string;
  tbsAlgorithmOid: string;
  spki: { algorithmOid: string; keyBytes: Uint8Array };
  signature: Uint8Array;
  selfIssued: boolean;
  /** Uppercase hex SHA-256 of the DER. */
  fingerprintSha256: string;
}

export async function parseCertificate(
  buf: Uint8Array,
  off = 0,
): Promise<Certificate> {
  const cert = expect(readTLV(buf, off), TAG.SEQUENCE, "Certificate");
  const [tbs, sigAlg, sigVal] = children(buf, cert);
  if (!tbs || !sigAlg || !sigVal)
    throw new ParseError("DER: Certificate needs 3 elements");
  expect(tbs, TAG.SEQUENCE, "TBSCertificate");
  const f = children(buf, tbs);
  let i = 0;
  if (f[0]?.tag === 0xa0) i++; // [0] EXPLICIT version
  const need = (n: TLV | undefined, what: string): TLV => {
    if (!n) throw new ParseError(`DER: TBSCertificate missing ${what}`);
    return n;
  };
  const serial = integerHex(buf, need(f[i++], "serialNumber"));
  const tbsAlg = need(f[i++], "signature");
  const issuer = parseName(buf, need(f[i++], "issuer"));
  const validity = children(buf, need(f[i++], "validity"));
  const subject = parseName(buf, need(f[i++], "subject"));
  const [spkiAlg, spkiKey] = children(
    buf,
    need(f[i++], "subjectPublicKeyInfo"),
  );
  const firstOid = (n: TLV | undefined, what: string): string => {
    const k = children(buf, need(n, what))[0];
    return oid(buf, need(k, `${what} algorithm`));
  };
  const der = rawOf(buf, cert);
  return {
    der,
    tbs: rawOf(buf, tbs),
    serial,
    subject,
    issuer,
    notBefore: time(buf, need(validity[0], "notBefore")),
    notAfter: time(buf, need(validity[1], "notAfter")),
    algorithmOid: firstOid(sigAlg, "signatureAlgorithm"),
    tbsAlgorithmOid: firstOid(tbsAlg, "signature"),
    spki: {
      algorithmOid: firstOid(spkiAlg, "spki.algorithm"),
      keyBytes: bitString(buf, need(spkiKey, "spki.subjectPublicKey")),
    },
    signature: bitString(buf, sigVal),
    selfIssued: equalBytes(issuer.raw, subject.raw),
    fingerprintSha256: hex(await sha256(der)).toUpperCase(),
  };
}

/** Parse a SEQUENCE OF Certificate located at `node`. */
export async function parseCertificateList(
  buf: Uint8Array,
  node: TLV,
): Promise<Certificate[]> {
  expect(node, TAG.SEQUENCE, "SEQUENCE OF Certificate");
  const out: Certificate[] = [];
  for (const c of children(buf, node))
    out.push(await parseCertificate(buf, c.start));
  if (!out.length) throw new ParseError("certificate bundle is empty");
  return out;
}
