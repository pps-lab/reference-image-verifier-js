#!/usr/bin/env node
// reference-image <photo> [--json] [--trust-anchor root.cer]...
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { verifyReferenceImage } from "./provenance.ts";
import { VERSION } from "./version.ts";

const USAGE = `Usage: reference-image [options] <photo.heic|photo.jpg>

Verify the Apple Reference Image signature of an iPhone photo.

Options:
  --json                 Print the full JSON report instead of a summary
  --trust-anchor <file>  Root certificate (DER) to trust instead of the
                         built-in Apple Prove root; may be repeated
  -h, --help             Show this help
  -v, --version          Print the version

Exit status: 0 when the verdict is "pass", 1 otherwise.`;

let args: ReturnType<typeof parseArgs<typeof SPEC>>;
const SPEC = {
  options: {
    json: { type: "boolean", default: false },
    "trust-anchor": { type: "string", multiple: true },
    help: { type: "boolean", short: "h", default: false },
    version: { type: "boolean", short: "v", default: false },
  },
  allowPositionals: true,
} as const;
try {
  args = parseArgs(SPEC);
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  console.error(USAGE);
  process.exit(2);
}
if (args.values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (args.values.version) {
  console.log(VERSION);
  process.exit(0);
}
const [file, extra] = args.positionals;
if (!file || extra !== undefined) {
  console.error(USAGE);
  process.exit(2);
}

const bytes = new Uint8Array(await readFile(file));
const anchorPaths = args.values["trust-anchor"] ?? [];
const trustAnchors = await Promise.all(
  anchorPaths.map(async (p) => new Uint8Array(await readFile(p))),
);
const { report } = await verifyReferenceImage(bytes, {
  fileName: file,
  ...(trustAnchors.length ? { trustAnchors } : {}),
});

if (args.values.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`${report.verdict.status.toUpperCase()}  ${file}`);
  for (const r of report.verdict.reasons) console.log(`  ${r}`);
  if (report.signature) {
    const h = (ok: boolean) => (ok ? "ok" : "FAIL");
    console.log(
      `  signature: ML-DSA-87 ${h(report.signature.mldsa.valid)}, RSA-3072-PSS ${h(report.signature.rsa.valid)}`,
    );
  }
  for (const c of report.certificates) {
    const status = c.signature.valid && c.withinValidity ? "ok" : "FAIL";
    console.log(
      `  ${c.role.padEnd(12)} ${c.subjectCN ?? c.subject}  [${status}]`,
    );
  }
}
process.exit(report.verdict.status === "pass" ? 0 : 1);
