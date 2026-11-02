const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAP = new Map([...ALPHABET].map((c, i) => [c, i]));

export function b58decode(input: string): Uint8Array {
  let n = 0n;
  for (const c of input) {
    const v = MAP.get(c);
    if (v === undefined) throw new Error(`invalid base58 character "${c}"`);
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of input) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

export function b58encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

/** Decodes `ed25519:<base58>` or `<base58>` into raw key/signature bytes. */
export function parseKeyLike(value: string): Uint8Array {
  const colon = value.indexOf(":");
  return b58decode(colon === -1 ? value : value.slice(colon + 1));
}
