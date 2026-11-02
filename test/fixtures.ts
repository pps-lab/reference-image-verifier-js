// Fixture lookup. The real photos and the root certificate are not committed;
// set REFERENCE_IMAGE_FIXTURES or drop them into test/fixtures/ (gitignored).
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURES =
  process.env.REFERENCE_IMAGE_FIXTURES ??
  fileURLToPath(new URL("./fixtures/", import.meta.url));

export const fixturePath = (name: string): string => path.join(FIXTURES, name);
export const hasFixture = (name: string): boolean =>
  existsSync(fixturePath(name));
export const loadFixture = async (name: string): Promise<Uint8Array> =>
  new Uint8Array(await readFile(fixturePath(name)));

export const NOW = "2026-10-31T12:00:00Z";
