import { ed25519 } from "@noble/curves/ed25519.js";
import { b58decode, b58encode } from "./base58.js";
import { bstr, bvec, concat, equalBytes, sha256, u8, u64, u128 } from "./borsh.js";
import { combineHash } from "./merkle.js";
import type {
  Check,
  LightClientBlockLiteView,
  LightClientBlockView,
  ValidatorStake,
  VerifiedLightClientHead,
} from "./types.js";

/**
 * Borsh layout of `BlockHeaderInnerLite` (nearcore `core/primitives/src/block_header.rs`):
 * height, epoch_id, next_epoch_id, prev_state_root, outcome_root, timestamp,
 * next_bp_hash, block_merkle_root.
 */
export function borshInnerLite(lite: LightClientBlockView["inner_lite"]): Uint8Array {
  const timestamp = BigInt(lite.timestamp_nanosec ?? lite.timestamp);
  return concat(
    u64(lite.height),
    b58decode(lite.epoch_id),
    b58decode(lite.next_epoch_id),
    b58decode(lite.prev_state_root),
    b58decode(lite.outcome_root),
    u64(timestamp),
    b58decode(lite.next_bp_hash),
    b58decode(lite.block_merkle_root),
  );
}

/**
 * Block hash from the light-weight view (nomicon ChainSpec):
 * `sha256(sha256(sha256(borsh(inner_lite)) ‖ inner_rest_hash) ‖ prev_block_hash)`.
 */
export function lightClientBlockHash(lite: LightClientBlockLiteView): Uint8Array {
  const innerLiteHash = sha256(borshInnerLite(lite.inner_lite));
  const innerHash = sha256(innerLiteHash, b58decode(lite.inner_rest_hash));
  return sha256(innerHash, b58decode(lite.prev_block_hash));
}

/**
 * Message validators sign for the block after next (nomicon ChainSpec):
 * `borsh(ApprovalInner::Endorsement(next_block_hash)) ‖ u64_le(height + 2)`.
 */
export function approvalMessage(nextBlockHash: Uint8Array, height: number): Uint8Array {
  return concat(u8(0), nextBlockHash, u64(height + 2));
}

/** `next_block_hash = sha256(next_block_inner_hash ‖ current_block_hash)`. */
export function nextBlockHash(view: LightClientBlockView, currentBlockHash: Uint8Array): Uint8Array {
  return combineHash(b58decode(view.next_block_inner_hash), currentBlockHash);
}

/** Borsh of `Vec<ValidatorStakeView>` (`ValidatorStakeView::V1` = tag 0). */
export function borshValidatorStakes(stakes: readonly ValidatorStake[]): Uint8Array {
  return bvec(stakes, (v) =>
    concat(
      u8(0),
      bstr(v.account_id),
      u8(0), // PublicKey::ED25519
      b58decode(v.public_key.slice(v.public_key.indexOf(":") + 1)),
      u128(BigInt(v.stake)),
    ),
  );
}

export interface ValidateOptions {
  /** The currently trusted head; omit only when you accept this block on trust (bootstrap). */
  head?: { inner_lite: LightClientBlockView["inner_lite"] } | null;
  /**
   * The set that signed this block — the *previous* epoch's producer set (`next_bps` of the view
   * before it). When supplied, approvals are checked against these keys instead of the ones the RPC
   * handed us, which is what makes the check meaningful.
   *
   * Do **not** pass `view.next_bps`: that is the set for the *following* epoch (committed by
   * `next_bp_hash`), not the one whose signatures appear here.
   */
  validators?: ValidatorStake[];
}

/** How many signatures may be resolved by key before we decide the set is simply wrong. */
const MAX_UNMATCHED = 40;

/**
 * Verifies a `LightClientBlockView` exactly as an external light client would (nomicon ChainSpec):
 * block-hash derivation, ed25519 approvals over the endorsement message, the >2/3 stake
 * threshold, and the `next_bp_hash` commitment to the validator set.
 *
 * Approvals are indexed by the *signing set's* order, but a set obtained from a neighbouring epoch
 * can list the same validators in a different order (equal stakes are tie-broken independently).
 * A signature is therefore attributed to whichever key in the set actually produced it: index first,
 * then by key. That cannot be gamed — a signature only verifies under the key that signed it.
 *
 * Note: when `validators` is not supplied the signer set comes from the same RPC response, so the
 * result is only *self-consistent*. Pass a pinned set (see `checkpoint.ts`) to anchor it.
 */
export function verifyLightClientBlock(
  view: LightClientBlockView,
  options: ValidateOptions = {},
): VerifiedLightClientHead {
  const checks: Check[] = [];
  const blockHash = lightClientBlockHash(view);
  const nextHash = nextBlockHash(view, blockHash);
  const message = approvalMessage(nextHash, view.inner_lite.height);

  const bps = options.validators ?? view.next_bps ?? [];
  const approvals = view.approvals_after_next ?? [];
  const credited = new Array<boolean>(bps.length).fill(false);
  const rawKeys = bps.map((v) => {
    const key = v.public_key;
    return b58decode(key.slice(key.indexOf(":") + 1));
  });
  const verify = (signature: string, key: Uint8Array): boolean => {
    try {
      return ed25519.verify(b58decode(signature.slice(signature.indexOf(":") + 1)), message, key);
    } catch {
      return false;
    }
  };

  // Pass 1: the signature sits at its validator's index, which is the case for a correctly ordered set.
  const unmatched: string[] = [];
  for (let i = 0; i < approvals.length; i++) {
    const signature = approvals[i];
    if (!signature) continue;
    if (i < bps.length && verify(signature, rawKeys[i])) credited[i] = true;
    else unmatched.push(signature);
  }

  // Pass 2: orderings can differ, so attribute the remainder by key.
  let resolvedByKey = 0;
  if (unmatched.length > 0 && unmatched.length <= MAX_UNMATCHED) {
    for (const signature of unmatched) {
      const index = bps.findIndex((_, j) => !credited[j] && verify(signature, rawKeys[j]));
      if (index >= 0) {
        credited[index] = true;
        resolvedByKey++;
      }
    }
  }

  let totalStake = 0n;
  let approvedStake = 0n;
  let invalid = 0;
  for (let i = 0; i < bps.length; i++) {
    const stake = BigInt(bps[i].stake);
    totalStake += stake;
    if (credited[i]) approvedStake += stake;
  }
  // Signatures that matched nobody in this set. Only meaningful when the set covers the signers.
  invalid = unmatched.length - resolvedByKey;

  const stakeOk = totalStake > 0n && approvedStake * 3n > totalStake * 2n;
  const approvedPercent = totalStake === 0n ? 0 : Number((approvedStake * 10000n) / totalStake) / 100;
  checks.push({
    name: "approvals signed by >2/3 of validator stake",
    ok: stakeOk,
    detail: `${approvedPercent}% of ${Number(totalStake / 10n ** 24n)}M NEAR${
      resolvedByKey ? `, ${resolvedByKey} matched by key` : ""
    }${invalid > 0 ? `, ${invalid} matched no key` : ""}`,
  });

  if (view.next_bps) {
    const bpsHash = sha256(borshValidatorStakes(view.next_bps));
    const ok = equalBytes(bpsHash, b58decode(view.inner_lite.next_bp_hash));
    checks.push({
      name: "validator set committed by next_bp_hash",
      ok,
      detail: `${view.next_bps.length} validators`,
    });
  }

  if (options.head) {
    const head = options.head.inner_lite;
    const epochOk =
      view.inner_lite.epoch_id === head.epoch_id || view.inner_lite.epoch_id === head.next_epoch_id;
    checks.push({ name: "epoch follows the trusted head (ChainSpec rule 2)", ok: epochOk });
    checks.push({
      name: "head moves forward (ChainSpec rule 1)",
      ok: view.inner_lite.height > head.height,
      detail: `${head.height} → ${view.inner_lite.height}`,
    });
  }

  return {
    blockHash,
    height: view.inner_lite.height,
    epochId: view.inner_lite.epoch_id,
    blockMerkleRoot: b58decode(view.inner_lite.block_merkle_root),
    outcomeRoot: b58decode(view.inner_lite.outcome_root),
    approvedStakePercent: approvedPercent,
    signatureCount: view.approvals_after_next?.filter(Boolean).length ?? 0,
    checks,
  };
}

export const lightClientHeadHash = (head: VerifiedLightClientHead): string => b58encode(head.blockHash);
