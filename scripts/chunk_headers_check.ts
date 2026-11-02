// Reproduce `chunk_headers_root` from the block's chunk views, so a specific shard's
// `prev_state_root` becomes authenticated by the light client head.
//
//   npx tsx scripts/chunk_headers_check.ts
import { b58decode } from "../src/base58.js";
import { sha256 } from "../src/borsh.js";
import { bytesToHex } from "../src/bytes.js";
import { merklize } from "../src/merkle.js";

const RPC = process.env.RPC ?? "https://free.rpc.fastnear.com";
async function jrpc(method: string, params: unknown): Promise<any> {
  const r = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "1", method, params }),
  });
  const j: any = await r.json();
  if (j.error) throw new Error((j.error.cause?.info?.error_message ?? j.error.message ?? "").slice(0, 140));
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
const u16 = (n: number) => {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
};
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
const u128 = (n: number | string) => {
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

function signature(sig: string): Uint8Array {
  const [kind, body] = sig.split(":");
  return kind === "ed25519" ? cat(u8(0), b58decode(body)) : cat(u8(1), b58decode(body));
}

function validatorStake(v: any): Uint8Array {
  const [kind, body] = v.public_key.split(":");
  const key = kind === "ed25519" ? cat(u8(0), b58decode(body)) : cat(u8(1), b58decode(body));
  return cat(bstr(v.account_id), key, u128(v.stake));
}

function congestionInfo(v: any, tagBytes: 1 | 4): Uint8Array {
  const tag = tagBytes === 1 ? u8(0) : u32(0);
  return cat(
    tag,
    u128(v.delayed_receipts_gas),
    u128(v.buffered_receipts_gas),
    u64(v.receipt_bytes),
    u16(v.allowed_shard),
  );
}

function bandwidthRequests(v: any): Uint8Array {
  const inner = v?.V1 ?? v?.v1 ?? { requests: [] };
  return cat(u8(0), vec(inner.requests ?? [], () => new Uint8Array(0)));
}

/** `ShardChunkHeaderInner::V4` = tag 3, `V5` = tag 4. */
function chunkInner(c: any, variant: 4 | 5, congestionTag: 1 | 4): Uint8Array {
  return cat(
    u8(variant === 4 ? 3 : 4),
    h32(c.prev_block_hash),
    h32(c.prev_state_root),
    h32(c.outcome_root), // prev_outcome_root
    h32(c.encoded_merkle_root),
    u64(c.encoded_length),
    u64(c.height_created),
    u64(c.shard_id),
    u64(c.gas_used), // prev_gas_used
    u64(c.gas_limit),
    u128(c.balance_burnt), // prev_balance_burnt
    h32(c.outgoing_receipts_root), // prev_outgoing_receipts_root
    h32(c.tx_root),
    vec(c.validator_proposals ?? [], validatorStake),
    congestionInfo(c.congestion_info, congestionTag),
    bandwidthRequests(c.bandwidth_requests),
    ...(variant === 5 ? [c.proposed_split ? u8(1) : u8(0)] : []),
  );
}

/** `ShardChunkHeader::V3` = tag 2 → `{ inner, height_included, signature }`. */
function chunkHeader(c: any, variant: 4 | 5, congestionTag: 1 | 4): Uint8Array {
  return cat(u8(2), chunkInner(c, variant, congestionTag), u64(c.height_included), signature(c.signature));
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

// `chunk_headers_root` is inside the inner-rest, so take it from the header JSON for now; the
// inner_rest check proves that this value is the one the light client block commits to.
const target = block.header.chunk_headers_root;
console.log(`block ${height} · protocol ${block.header.latest_protocol_version} · ${block.chunks.length} chunks`);
console.log(`expected chunk_headers_root ${target}`);

// control: maybe it is a merkle root of the chunk hashes themselves
const byChunkHash = merklize(block.chunks.map((c: any) => h32(c.chunk_hash)));
console.log(`merklize(chunk_hash): ${bytesToHex(byChunkHash)} ${bytesToHex(byChunkHash) === bytesToHex(h32(target)) ? "MATCH" : ""}`);

// `chunk_hash = combine_hash(sha256(borsh(inner)), encoded_merkle_root)` (nearcore
// `ShardChunkHeaderV3::compute_hash`), which gives a per-chunk oracle for the inner encoding.
const first = block.chunks[0];
console.log(`\nper-chunk oracle on shard ${first.shard_id} (chunk_hash ${first.chunk_hash}):`);
for (const variant of [4, 5] as const) {
  for (const congestionTag of [1, 4] as const) {
    try {
      const innerHash = sha256(chunkInner(first, variant, congestionTag));
      const chunkHash = bytesToHex(sha256(innerHash, h32(first.encoded_merkle_root)));
      console.log(`  inner V${variant}, congestion ${congestionTag}B: ${chunkHash} ${chunkHash === bytesToHex(h32(first.chunk_hash)) ? "MATCH" : ""}`);
    } catch (error) {
      console.log(`  inner V${variant}, congestion ${congestionTag}B: ${error instanceof Error ? error.message : error}`);
    }
  }
}

// nearcore `BlockBody::compute_chunk_headers_root`:
//   merklize(&[ChunkHashHeight(chunk_hash, height_included)])
// and `chunk_hash` is itself recomputable from the inner header, so nothing here is taken on trust.
const expected = bytesToHex(h32(target));
const leaves = block.chunks.map((c: any) => {
  const innerHash = sha256(chunkInner(c, 5, 1));
  const chunkHash = sha256(innerHash, h32(c.encoded_merkle_root));
  return sha256(chunkHash, u64(c.height_included));
});
const root = bytesToHex(merklize(leaves));
console.log(`\nmerklize(ChunkHashHeight) with recomputed chunk_hash: ${root} ${root === expected ? "MATCH" : ""}`);

for (const [label, candidate] of Object.entries({
  "recomputed chunk_hash": leaves,
  "view chunk_hash": block.chunks.map((c: any) => sha256(h32(c.chunk_hash), u64(c.height_included))),
})) {
  const r = bytesToHex(merklize(candidate as Uint8Array[]));
  console.log(`  ${label.padEnd(24)} ${r} ${r === expected ? "MATCH" : ""}`);
}
