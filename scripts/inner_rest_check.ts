// Reproduce `inner_rest_hash` from the JSON block header, so that every field of the inner-rest
// (notably `chunk_headers_root`) becomes authenticated by the light client block.
//
//   npx tsx scripts/inner_rest_check.ts
import { b58decode } from "../src/base58.js";
import { sha256 } from "../src/borsh.js";
import { bytesToHex } from "../src/bytes.js";

const RPC = process.env.RPC ?? "https://free.rpc.fastnear.com";
async function jrpc(method: string, params: unknown): Promise<any> {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "1", method, params }),
  });
  const j: any = await r.json();
  if (j.error) throw new Error((j.error.cause?.info?.error_message ?? j.error.message ?? "").slice(0, 120));
  return j.result;
}

const cat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};
const u8 = (n: number) => Uint8Array.of(n & 0xff);
const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const u64 = (n: number | string) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const u128 = (n: string | number) => {
  const b = new Uint8Array(16);
  let v = BigInt(n);
  for (let i = 0; i < 16; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
};
const bstr = (s: string) => {
  const b = new TextEncoder().encode(s);
  return cat(u32(b.length), b);
};
const vec = <T>(items: T[], enc: (t: T) => Uint8Array) => cat(u32(items.length), ...items.map(enc));
const h32 = (s: string) => b58decode(s);

/** `Signature`: u8 tag (0 = ED25519 + 64 bytes, 1 = SECP256K1 + 65) — nearcore `core/crypto/src/signature.rs`. */
function signature(sig: string): Uint8Array {
  const [kind, body] = sig.split(":");
  if (kind === "ed25519") return cat(u8(0), b58decode(body));
  if (kind === "secp256k1") return cat(u8(1), b58decode(body));
  throw new Error(`unsupported signature ${kind}`);
}

function option<T>(value: T | null | undefined, enc: (t: T) => Uint8Array): Uint8Array {
  return value === null || value === undefined ? u8(0) : cat(u8(1), enc(value));
}

function validatorStake(v: any): Uint8Array {
  const [kind, body] = v.public_key.split(":");
  const key = kind === "ed25519" ? cat(u8(0), b58decode(body)) : cat(u8(1), b58decode(body));
  return cat(bstr(v.account_id), key, u128(v.stake));
}

/** Shared head of V6/V7/V8 (fields 1-16 of the current structs). */
function innerRestV6(h: any): Uint8Array {
  return cat(
    h32(h.block_body_hash),
    h32(h.chunk_receipts_root), // prev_chunk_outgoing_receipts_root
    h32(h.chunk_headers_root),
    h32(h.chunk_tx_root),
    h32(h.random_value),
    vec(h.validator_proposals ?? [], validatorStake),
    vec(h.chunk_mask ?? [], (b: boolean) => u8(b ? 1 : 0)),
    u128(h.gas_price), // next_gas_price
    u128(h.total_supply),
    h32(h.last_final_block),
    h32(h.last_ds_final_block),
    u64(h.block_ordinal),
    u64(h.prev_height),
    option(h.epoch_sync_data_hash, h32),
    vec(h.approvals ?? [], (sig: string | null) => option(sig, signature)),
    u32(h.latest_protocol_version),
    vec(h.chunk_endorsements ?? [], (row: number[]) => cat(u32(row.length), Uint8Array.from(row))),
    option(h.shard_split, (split: any) => cat(u64(split[0] ?? split.shard_id), bstr(split[1] ?? split.account_id))),
  );
}

/** V7/V8 append the SPICE fields. */
function innerRestV8(h: any): Uint8Array {
  return cat(
    innerRestV6(h),
    h32(h.prev_last_certified_block_epoch_id ?? "11111111111111111111111111111111"),
    vec(h.spice_chunk_endorsement_stats ?? [], (s: any) => cat()),
  );
}

const head = await jrpc("block", { finality: "final" });
let lcb: any = null;
for (let back = 0; back < 6 && !lcb; back++) {
  const b = await jrpc("block", { block_id: Number(head.header.height) - back });
  const candidate = await jrpc("next_light_client_block", { last_block_hash: b.header.hash });
  if (candidate?.inner_lite) lcb = candidate;
}
const height = Number(lcb.inner_lite.height);
let block: any = null;
for (let i = 0; i < 20 && !block; i++) {
  try {
    block = await jrpc("block", { block_id: height });
  } catch {
    await new Promise((r) => setTimeout(r, 1200));
  }
}
const target = bytesToHex(b58decode(lcb.inner_rest_hash));
console.log(`lcb height ${height} · protocol ${block.header.latest_protocol_version}`);
console.log(`expected inner_rest_hash ${target}`);

for (const [label, fn] of [
  ["V6", innerRestV6],
  ["V8", innerRestV8],
] as const) {
  try {
    const encoded = fn(block.header);
    const got = bytesToHex(sha256(encoded));
    console.log(`${label}: len=${encoded.length} sha256=${got} ${got === target ? "MATCH" : ""}`);
  } catch (error) {
    console.log(`${label}: ${error instanceof Error ? error.message : error}`);
  }
}
