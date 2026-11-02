import { equalBytes, sha256 } from "./borsh.js";
import { bytesToHex as toHex } from "./bytes.js";

/**
 * NEAR shard-state (Merkle-Patricia) proof verification.
 *
 * A proof is a path of trie nodes from the state root to the key being read. Every node is
 * `borsh(RawTrieNodeWithSize)` and its hash is `sha256(borsh(RawTrieNodeWithSize))`, so a verifier
 * can walk from a trusted root, requiring each child hash to be present in the proof. A node that
 * is missing (or has been altered) changes the hash and the walk stops.
 *
 * Sources: `core/store/src/trie/raw_node.rs`, `nibble_slice.rs`, `trie_key.rs`.
 */

export interface ValueRef {
  length: number;
  hash: Uint8Array;
}

export type RawTrieNode =
  | { kind: "leaf"; key: Uint8Array; value: ValueRef }
  | { kind: "branchNoValue"; children: (Uint8Array | null)[] }
  | { kind: "branchWithValue"; value: ValueRef; children: (Uint8Array | null)[] }
  | { kind: "extension"; key: Uint8Array; child: Uint8Array };

export interface DecodedTrieNode {
  node: RawTrieNode;
  memoryUsage: bigint;
  /** `sha256(borsh(node))` — the hash the parent must point at. */
  hash: Uint8Array;
}

class Reader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  take(n: number): Uint8Array {
    if (this.offset + n > this.bytes.length) throw new Error("trie node is truncated");
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  u8(): number {
    return this.take(1)[0];
  }

  u16(): number {
    const b = this.take(2);
    return b[0] | (b[1] << 8);
  }

  u32(): number {
    const b = this.take(4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }

  u64(): bigint {
    const b = this.take(8);
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(b[i]);
    return value;
  }

  byteVec(): Uint8Array {
    return this.take(this.u32());
  }

  valueRef(): ValueRef {
    const length = this.u32();
    const hash = this.take(32);
    return { length, hash };
  }

  /** `Children`: a u16 bitmap, then the present child hashes in ascending index order. */
  children(): (Uint8Array | null)[] {
    const bitmap = this.u16();
    const out: (Uint8Array | null)[] = new Array(16).fill(null);
    for (let i = 0; i < 16; i++) {
      if (bitmap & (1 << i)) out[i] = this.take(32);
    }
    return out;
  }
}

export function decodeTrieNode(bytes: Uint8Array): DecodedTrieNode {
  const reader = new Reader(bytes);
  const tag = reader.u8();
  let node: RawTrieNode;
  switch (tag) {
    case 0:
      node = { kind: "leaf", key: reader.byteVec(), value: reader.valueRef() };
      break;
    case 1:
      node = { kind: "branchNoValue", children: reader.children() };
      break;
    case 2:
      node = { kind: "branchWithValue", value: reader.valueRef(), children: reader.children() };
      break;
    case 3:
      node = { kind: "extension", key: reader.byteVec(), child: reader.take(32) };
      break;
    default:
      throw new Error(`unknown trie node type ${tag}`);
  }
  const memoryUsage = reader.u64();
  if (reader.remaining !== 0) throw new Error(`trie node has ${reader.remaining} trailing bytes`);
  return { node, memoryUsage, hash: sha256(bytes) };
}

/** Hex-prefix ("HP") encoded nibble path → nibble values. */
export function decodeEncodedKey(encoded: Uint8Array): number[] {
  if (encoded.length === 0) return [];
  const offset = (encoded[0] & 0x10) !== 0 ? 1 : 2;
  const nibbles: number[] = [];
  for (const byte of encoded) nibbles.push(byte >> 4, byte & 0x0f);
  return nibbles.slice(offset);
}

/** Little-endian nibble path of an arbitrary key. */
export function keyNibbles(key: Uint8Array): number[] {
  const nibbles: number[] = [];
  for (const byte of key) nibbles.push(byte >> 4, byte & 0x0f);
  return nibbles;
}

/** Trie key for a contract-storage entry: `[col::CONTRACT_DATA] account_id ',' key`. */
export function contractDataKey(accountId: string, key: Uint8Array): Uint8Array {
  const account = new TextEncoder().encode(accountId);
  const out = new Uint8Array(1 + account.length + 1 + key.length);
  out[0] = 9; // col::CONTRACT_DATA
  out.set(account, 1);
  out[1 + account.length] = 0x2c; // ACCOUNT_DATA_SEPARATOR (',')
  out.set(key, 2 + account.length);
  return out;
}

export interface StateProofResult {
  /** root recomputed by folding the proof from the root node */
  root: Uint8Array;
  /** whether the key exists in the trie */
  found: boolean;
  /** the value committed by the leaf, when `found` */
  valueHash?: Uint8Array;
  valueLength?: number;
  /** number of trie nodes walked */
  steps: number;
}

/**
 * Walks `key` from `stateRoot` through `proof` nodes and returns what the trie commits to.
 * The caller must separately confirm `result.root` equals the trusted state root, and that the
 * bytes it was handed hash to `result.valueHash`.
 */
export function verifyStateProof(
  proof: readonly Uint8Array[],
  key: Uint8Array,
  expectedValue?: Uint8Array,
): StateProofResult {
  if (proof.length === 0) throw new Error("empty state proof");

  const byHash = new Map<string, DecodedTrieNode>();
  let root: DecodedTrieNode | null = null;
  for (const [index, bytes] of proof.entries()) {
    const decoded = decodeTrieNode(bytes);
    const id = toHex(decoded.hash);
    if (byHash.has(id)) continue;
    byHash.set(id, decoded);
    if (index === 0) root = decoded;
  }
  if (!root) throw new Error("state proof has no root node");
  const rootNode: DecodedTrieNode = root;

  const nibbles = keyNibbles(key);
  let current = rootNode;
  let position = 0;
  let steps = 0;

  for (;;) {
    steps++;
    const node = current.node;
    if (steps > 4096) throw new Error("state proof does not terminate");

    if (node.kind === "leaf") {
      const leafNibbles = decodeEncodedKey(node.key);
      const rest = nibbles.slice(position);
      const matches = leafNibbles.length === rest.length && leafNibbles.every((n, i) => n === rest[i]);
      if (!matches) return { root: rootNode.hash, found: false, steps };
      return {
        root: root.hash,
        found: true,
        valueHash: node.value.hash,
        valueLength: node.value.length,
        steps,
      };
    }

    if (node.kind === "branchWithValue" && position === nibbles.length) {
      return {
        root: root.hash,
        found: true,
        valueHash: node.value.hash,
        valueLength: node.value.length,
        steps,
      };
    }

    if (node.kind === "extension") {
      const extensionNibbles = decodeEncodedKey(node.key);
      const slice = nibbles.slice(position, position + extensionNibbles.length);
      if (slice.length !== extensionNibbles.length) return { root: rootNode.hash, found: false, steps };
      if (!extensionNibbles.every((n, i) => n === slice[i])) return { root: rootNode.hash, found: false, steps };
      position += extensionNibbles.length;
      const child = byHash.get(toHex(node.child));
      if (!child) throw new Error("state proof is missing the extension's child node");
      current = child;
      continue;
    }

    if (position >= nibbles.length) return { root: rootNode.hash, found: false, steps };
    const children = node.kind === "branchNoValue" ? node.children : node.children;
    const childHash = children[nibbles[position]];
    if (!childHash) return { root: rootNode.hash, found: false, steps };
    position += 1;
    const child = byHash.get(toHex(childHash));
    if (!child) throw new Error("state proof is missing a branch child node");
    current = child;
  }

  // Unreachable, but keeps the compiler honest about the return type.
  // eslint-disable-next-line no-unreachable
  return { root: rootNode.hash, found: false, steps };
}

/** True when the bytes an RPC returned are the ones the leaf commits to. */
export function valueMatchesRef(value: Uint8Array, ref: { length: number; hash: Uint8Array }): boolean {
  return value.length === ref.length && equalBytes(sha256(value), ref.hash);
}

