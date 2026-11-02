import { b58decode } from "./base58.js";
import { concat, equalBytes, sha256, u128, u32, u64, u8 } from "./borsh.js";
import { merklize } from "./merkle.js";
import type { Check, LightClientBlockView } from "./types.js";

/**
 * Reproduces the block-header commitments that a light client block already authenticates, so a
 * shard's state root stops being something the RPC told us and becomes something validators signed.
 *
 * Two hashes have to be reproduced, and both are self-checking:
 *
 *   sha256(borsh(BlockHeaderInnerRest))  == light_client_block.inner_rest_hash
 *   merklize(ChunkHashHeight)            == inner_rest.chunk_headers_root
 *
 * The second needs each chunk's hash, which is itself recomputed here from the chunk's inner header
 * (`chunk_hash = sha256(sha256(borsh(inner)) ‖ encoded_merkle_root)`), so a lying RPC cannot smuggle
 * in a state root of its own: it would have to invert sha256.
 *
 * Layouts verified against nearcore protocol 86:
 *   core/primitives/src/block_header.rs        (BlockHeaderInnerRestV6)
 *   core/primitives/src/sharding.rs            (ShardChunkHeaderV3, ChunkHashHeight)
 *   core/primitives/src/sharding/shard_chunk_header_inner.rs (ShardChunkHeaderInnerV5)
 *   core/primitives/src/block.rs               (compute_chunk_headers_root)
 */

/** `BlockHeaderInnerRestV6`: the variant used from the congestion-control protocol onwards. */
export function encodeInnerRest(header: any): Uint8Array {
  return concat(
    b58decode(header.block_body_hash),
    b58decode(header.chunk_receipts_root), // prev_chunk_outgoing_receipts_root
    b58decode(header.chunk_headers_root),
    b58decode(header.chunk_tx_root),
    b58decode(header.random_value),
    // prev_validator_proposals
    bvec(header.validator_proposals ?? [], encodeValidatorStake),
    // chunk_mask
    bvec(header.chunk_mask ?? [], (flag: boolean) => u8(flag ? 1 : 0)),
    u128(BigInt(header.gas_price)), // next_gas_price
    u128(BigInt(header.total_supply)),
    b58decode(header.last_final_block),
    b58decode(header.last_ds_final_block),
    u64(header.block_ordinal),
    u64(header.prev_height),
    // epoch_sync_data_hash: Option<CryptoHash>
    header.epoch_sync_data_hash ? concat(u8(1), b58decode(header.epoch_sync_data_hash)) : u8(0),
    // approvals: Vec<Option<Signature>>
    bvec(header.approvals ?? [], (sig: string | null) => (sig ? concat(u8(1), encodeSignature(sig)) : u8(0))),
    u32(header.latest_protocol_version),
    // chunk_endorsements: Vec<Vec<u8>>
    bvec(header.chunk_endorsements ?? [], (row: number[]) => concat(u32(row.length), Uint8Array.from(row))),
    // shard_split: Option<(ShardId, AccountId)>
    header.shard_split ? concat(u8(1), u64(header.shard_split.shard_id ?? 0), encodeAccount(header.shard_split.account_id ?? "")) : u8(0),
  );
}

const bvec = <T>(items: readonly T[], encode: (item: T) => Uint8Array): Uint8Array =>
  concat(u32(items.length), ...items.map(encode));

const encodeAccount = (accountId: string): Uint8Array => {
  const bytes = new TextEncoder().encode(accountId);
  return concat(u32(bytes.length), bytes);
};

/** `PublicKey`: u8 tag + key bytes (nearcore hand-written Borsh impl). */
function encodePublicKey(publicKey: string): Uint8Array {
  const [kind, body] = publicKey.split(":");
  const raw = b58decode(body);
  return kind === "ed25519" ? concat(u8(0), raw) : concat(u8(1), raw);
}

/** `Signature`: u8 tag + signature bytes. */
function encodeSignature(signature: string): Uint8Array {
  const [kind, body] = signature.split(":");
  const raw = b58decode(body);
  return kind === "ed25519" ? concat(u8(0), raw) : concat(u8(1), raw);
}

function encodeValidatorStake(stake: any): Uint8Array {
  return concat(encodeAccount(stake.account_id), encodePublicKey(stake.public_key), u128(BigInt(stake.stake)));
}

/**
 * `ShardChunkHeaderInner::V5` (tag 4):
 * prev_block_hash, prev_state_root, prev_outcome_root, encoded_merkle_root, encoded_length,
 * height_created, shard_id, prev_gas_used, gas_limit, prev_balance_burnt,
 * prev_outgoing_receipts_root, tx_root, prev_validator_proposals, congestion_info,
 * bandwidth_requests, proposed_split.
 */
export function encodeChunkInner(chunk: any): Uint8Array {
  const congestion = chunk.congestion_info ?? {};
  const bandwidth = chunk.bandwidth_requests;
  return concat(
    u8(4), // ShardChunkHeaderInner::V5
    b58decode(chunk.prev_block_hash),
    b58decode(chunk.prev_state_root),
    b58decode(chunk.outcome_root),
    b58decode(chunk.encoded_merkle_root),
    u64(chunk.encoded_length),
    u64(chunk.height_created),
    u64(chunk.shard_id),
    u64(chunk.gas_used),
    u64(chunk.gas_limit),
    u128(BigInt(chunk.balance_burnt)),
    b58decode(chunk.outgoing_receipts_root),
    b58decode(chunk.tx_root),
    bvec(chunk.validator_proposals ?? [], encodeValidatorStake),
    // CongestionInfo::V1 (u8 discriminant)
    concat(
      u8(0),
      u128(BigInt(congestion.delayed_receipts_gas ?? 0)),
      u128(BigInt(congestion.buffered_receipts_gas ?? 0)),
      u64(congestion.receipt_bytes ?? 0),
      u16le(congestion.allowed_shard ?? 0),
    ),
    // BandwidthRequests::V1 { requests }
    concat(u8(0), bvec((bandwidth?.V1 ?? bandwidth?.v1)?.requests ?? [], () => new Uint8Array(0))),
    // proposed_split: Option<TrieSplit>
    chunk.proposed_split ? concat(u8(1), encodeTrieSplit(chunk.proposed_split)) : u8(0),
  );
}

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

function encodeTrieSplit(split: any): Uint8Array {
  const splitShard = split.shard_id ?? split.split_shard_id ?? 0;
  const boundary = split.boundary_account ?? split.account_id ?? "";
  return concat(u64(splitShard), encodeAccount(String(boundary)));
}

/** `chunk_hash = sha256(sha256(borsh(inner)) ‖ encoded_merkle_root)` (nearcore `compute_hash`). */
export function chunkHash(chunk: any): Uint8Array {
  return sha256(sha256(encodeChunkInner(chunk)), b58decode(chunk.encoded_merkle_root));
}

/** `merklize(&[ChunkHashHeight(chunk_hash, height_included)])`. */
export function chunkHeadersRoot(chunks: readonly any[]): Uint8Array {
  return merklize(chunks.map((chunk) => sha256(chunkHash(chunk), u64(chunk.height_included))));
}

export interface AuthenticatedRoots {
  /** shard id → the state root that shard's next chunk commits to */
  stateRoots: Map<number, string>;
  /** base58 of `chunk_headers_root`, once reproduced */
  chunkHeadersRoot: string;
  checks: Check[];
  /** the encoded inner-rest length, useful when the layout does not match the protocol */
  innerRestBytes: number;
}

/**
 * Checks that a block header's `chunk_headers_root` (and therefore every chunk's `prev_state_root`)
 * is committed by the light client block we already verified.
 */
export function authenticateBlockRoots(
  block: { header: any; chunks: any[] },
  head: LightClientBlockView,
): AuthenticatedRoots {
  const checks: Check[] = [];
  const innerRest = encodeInnerRest(block.header);
  const innerRestHash = sha256(innerRest);
  const expectedInnerRest = b58decode(head.inner_rest_hash);
  const innerRestOk = equalBytes(innerRestHash, expectedInnerRest);

  checks.push({
    name: "block header matches the head's inner_rest_hash",
    ok: innerRestOk,
    detail: innerRestOk
      ? `protocol ${block.header.latest_protocol_version}, ${innerRest.length} bytes`
      : "header layout does not match this protocol version",
  });

  const stateRoots = new Map<number, string>();
  let root = "";
  if (innerRestOk) {
    const computedRoot = chunkHeadersRoot(block.chunks ?? []);
    root = toB58(computedRoot);
    const chunksOk = equalBytes(computedRoot, b58decode(block.header.chunk_headers_root));
    checks.push({
      name: "chunk headers reproduce chunk_headers_root",
      ok: chunksOk,
      detail: `${block.chunks?.length ?? 0} chunks`,
    });
    if (chunksOk) {
      for (const chunk of block.chunks ?? []) stateRoots.set(chunk.shard_id, chunk.prev_state_root);
    }
  }

  return { stateRoots, chunkHeadersRoot: root, checks, innerRestBytes: innerRest.length };
}

const toB58 = (bytes: Uint8Array): string => {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
};
