import { b58decode } from "./base58.js";
import { concat, sha256 } from "./borsh.js";

/** One step of a NEAR merkle path. `Left` means the sibling sits on the left. */
export interface MerklePathItem {
  hash: string;
  direction: "Left" | "Right";
}

export type MerklePath = MerklePathItem[];

/** nearcore `core/primitives/src/merkle.rs::combine_hash`. */
export const combineHash = (a: Uint8Array, b: Uint8Array): Uint8Array => sha256(a, b);

/** nearcore `core/primitives/src/merkle.rs::compute_root_from_path`. */
export function computeRootFromPath(path: MerklePath, itemHash: Uint8Array): Uint8Array {
  let current = itemHash;
  for (const item of path) {
    const sibling = b58decode(item.hash);
    current = item.direction === "Left" ? combineHash(sibling, current) : combineHash(current, sibling);
  }
  return current;
}

/**
 * nearcore `verify_hash`: fold a path from `itemHash` and compare with `root`.
 */
export function verifyHash(root: Uint8Array, path: MerklePath, itemHash: Uint8Array): boolean {
  const computed = computeRootFromPath(path, itemHash);
  return computed.length === root.length && computed.every((v, i) => v === root[i]);
}

/** Computes a merkle root from a list of leaf hashes (nearcore `merklize`). */
export function merklize(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return new Uint8Array(32);
  let level = leaves.slice();
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? combineHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

export { concat };
