// Just enough TIFF/Exif to read the Apple MakerNote flag that marks a
// developed Reference Image (tag 0x0063 = 8). Informational only: the flag
// is unsigned and sits outside the signed processed image.

import { ascii } from "./util.ts";

export interface ExifSummary {
  make: string | null;
  model: string | null;
  software: string | null;
  dateTimeOriginal: string | null;
  /** e.g. "2.32" */
  exifVersion: string | null;
  /** Apple MakerNote tag 0x0063; 8 on developed Reference Images. */
  appleReferenceFlag: number | null;
}

interface Entry {
  type: number;
  count: number;
  valueOff: number;
}

function reader(t: Uint8Array, le: boolean) {
  const dv = new DataView(t.buffer, t.byteOffset, t.byteLength);
  return {
    u16: (o: number) => dv.getUint16(o, le),
    u32: (o: number) => dv.getUint32(o, le),
    u64: (o: number) => Number(dv.getBigUint64(o, le)),
  };
}
type Reader = ReturnType<typeof reader>;

function ifdEntries(t: Uint8Array, r: Reader, off: number): Map<number, Entry> {
  const n = r.u16(off);
  const out = new Map<number, Entry>();
  for (let k = 0; k < n; k++) {
    const e = off + 2 + 12 * k;
    if (e + 12 > t.length) break;
    out.set(r.u16(e), {
      type: r.u16(e + 2),
      count: r.u32(e + 4),
      valueOff: e + 8,
    });
  }
  return out;
}

/**
 * Read the handful of Exif fields the report shows.
 * @param tiff bytes starting at the TIFF header ("II*\0" or "MM\0*").
 */
export function readExif(tiff: Uint8Array): ExifSummary {
  const out: ExifSummary = {
    make: null,
    model: null,
    software: null,
    dateTimeOriginal: null,
    exifVersion: null,
    appleReferenceFlag: null,
  };
  try {
    const le = ascii(tiff, 0, 2) === "II";
    const r = reader(tiff, le);
    const ifd0 = ifdEntries(tiff, r, r.u32(4));
    const str = (e: Entry | undefined): string | null => {
      if (e?.type !== 2) return null;
      const o = e.count <= 4 ? e.valueOff : r.u32(e.valueOff);
      return ascii(tiff, o, e.count).replace(/\0+$/, "");
    };
    out.make = str(ifd0.get(0x010f));
    out.model = str(ifd0.get(0x0110));
    out.software = str(ifd0.get(0x0131));
    const exifPtr = ifd0.get(0x8769);
    if (!exifPtr) return out;
    const exif = ifdEntries(tiff, r, r.u32(exifPtr.valueOff));
    out.dateTimeOriginal = str(exif.get(0x9003));
    const ev = exif.get(0x9000); // UNDEFINED[4], e.g. "0232" = Exif 2.32
    if (ev?.type === 7 && ev.count === 4) {
      const d = ascii(tiff, ev.valueOff, 4);
      if (/^\d{4}$/.test(d))
        out.exifVersion = `${Number(d.slice(0, 2))}.${d.slice(2)}`;
    }
    const mn = exif.get(0x927c);
    if (!mn) return out;
    const mnOff = r.u32(mn.valueOff);
    const note = tiff.subarray(mnOff, mnOff + mn.count);
    if (ascii(note, 0, 9) !== "Apple iOS") return out;
    const nle = ascii(note, 12, 2) === "II";
    const nr = reader(note, nle);
    const entries = ifdEntries(note, nr, 14);
    const flag = entries.get(0x0063);
    if (flag) {
      // Type 16 (LONG8) does not fit the 4-byte field, so it is stored at an
      // offset relative to the MakerNote start.
      if (flag.type === 16 && flag.count === 1)
        out.appleReferenceFlag = nr.u64(nr.u32(flag.valueOff));
      else if (flag.type === 4) out.appleReferenceFlag = nr.u32(flag.valueOff);
      else if (flag.type === 3) out.appleReferenceFlag = nr.u16(flag.valueOff);
    }
  } catch {
    // Exif is best effort; never fail verification over it.
  }
  return out;
}
