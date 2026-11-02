import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "./bytes.js";

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return nobleSha256(buf);
}

export const u8 = (n: number): Uint8Array => Uint8Array.of(n & 0xff);

export function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export function u64(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

export function u128(n: bigint): Uint8Array {
  if (n < 0n || n >= 1n << 128n) throw new Error(`u128 out of range: ${n}`);
  const b = new Uint8Array(16);
  let v = n;
  for (let i = 0; i < 16; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** Borsh `String` / `AccountId`: u32 little-endian byte length + utf8 bytes. */
export function bstr(s: string): Uint8Array {
  const body = new TextEncoder().encode(s);
  return concat(u32(body.length), body);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Borsh `Vec<T>`. */
export function bvec<T>(items: readonly T[], encode: (item: T) => Uint8Array): Uint8Array {
  return concat(u32(items.length), ...items.map(encode));
}

export const toHex = bytesToHex;

export const fromHex = hexToBytes;

export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);
