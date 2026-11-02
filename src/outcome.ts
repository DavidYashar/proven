import { b58decode } from "./base58.js";
import { base64ToBytes } from "./bytes.js";
import { bstr, bvec, concat, equalBytes, sha256, u8, u32, u64, u128 } from "./borsh.js";
import { computeRootFromPath, verifyHash } from "./merkle.js";
import type { Check, ExecutionOutcomeView, LightClientProof } from "./types.js";

/**
 * nearcore `core/primitives/src/transaction.rs`:
 *
 * ```text
 * ExecutionOutcomeWithId::to_hashes() = [ id,
 *                                         sha256(borsh(PartialExecutionOutcome)),
 *                                         sha256(log_0), sha256(log_1), … ]
 * ```
 *
 * `PartialExecutionOutcome` deliberately excludes `logs` and `metadata` (so the
 * `ExecutionMetadata::V4` profile blob never has to be re-encoded client side).
 *
 * NOTE: `docs/ChainSpec/LightClient.md` documents the leaf as
 * `sha256(borsh(execution_outcome))`, which does **not** match the implementation.
 * The recipe below is the one nearcore actually builds (`test-loop-tests/src/tests/light_client.rs`).
 */
export function outcomeToHashes(id: string, outcome: ExecutionOutcomeView): Uint8Array[] {
  const status = (() => {
    const view: any = outcome.status;
    // PartialExecutionStatus::Failure carries no payload: "Excludes failure debug info"
    // (`core/primitives/src/transaction.rs`), so a failed outcome hashes to a single byte.
    if (view?.Failure !== undefined || view === "Failure") return u8(1);
    if (outcome.status.SuccessValue !== undefined) {
      const value = base64ToBytes(outcome.status.SuccessValue);
      return concat(u8(2), u32(value.length), value);
    }
    if (outcome.status.SuccessReceiptId !== undefined) {
      return concat(u8(3), b58decode(outcome.status.SuccessReceiptId));
    }
    throw new Error(`cannot hash outcome with status ${JSON.stringify(view)}`);
  })();

  const partial = concat(
    bvec(outcome.receipt_ids ?? [], b58decode),
    u64(outcome.gas_burnt),
    u128(BigInt(outcome.tokens_burnt)),
    bstr(outcome.executor_id),
    status,
  );

  const logs = (outcome.logs ?? []).map((log) => {
    if (typeof log !== "string") {
      throw new Error("log entries must be strings (nearcore `LogEntry` is a String since 2.x)");
    }
    return sha256(new TextEncoder().encode(log));
  });

  return [b58decode(id), sha256(partial), ...logs];
}

/** borsh(`Vec<CryptoHash>`) — how the merkle tree hashes a whole outcome item. */
export const outcomeItemHash = (hashes: Uint8Array[]): Uint8Array =>
  sha256(u32(hashes.length), ...hashes);

export interface OutcomeVerification {
  checks: Check[];
  verified: boolean;
  /** root that the caller must additionally check against the light client head */
  blockOutcomeRoot: Uint8Array;
  outcomeRootProof: LightClientProof["outcome_root_proof"];
}

/**
 * Verifies `outcome_proof` up to the `outcome_root` committed in the block header
 * (the second half — proving that header belongs to the trusted head — is done separately).
 */
export function verifyOutcomeRoot(
  proof: LightClientProof,
  expectedOutcomeRoot: Uint8Array,
): OutcomeVerification {
  const checks: Check[] = [];
  const op = proof.outcome_proof;
  const hashes = outcomeToHashes(op.id, op.outcome);
  const chunkRoot = computeRootFromPath(op.proof, outcomeItemHash(hashes));
  const blockOutcomeRoot = computeRootFromPath(proof.outcome_root_proof, sha256(chunkRoot));

  checks.push({
    name: "execution outcome is committed by the block's outcome_root",
    ok: equalBytes(blockOutcomeRoot, expectedOutcomeRoot),
    detail: `${hashes.length} leaf hash(es), ${op.proof.length}+${proof.outcome_root_proof.length} path steps`,
  });

  return {
    checks,
    verified: checks.every((c) => c.ok),
    blockOutcomeRoot,
    outcomeRootProof: proof.outcome_root_proof,
  };
}

/** Verifies that the outcome's block is included in the trusted head's block merkle tree. */
export function verifyBlockInclusion(
  proof: LightClientProof,
  blockHash: Uint8Array,
  headBlockMerkleRoot: Uint8Array,
  headBlockHash?: Uint8Array,
): Check {
  // When the proven block *is* the light client head, nearcore returns an empty path and the
  // block is included by identity — this is the common case for "verify the transaction I just
  // sent", so it must not be reported as a failure.
  if (headBlockHash && equalBytes(blockHash, headBlockHash)) {
    return {
      name: "block is the light client head itself",
      ok: true,
      detail: "no merkle path needed",
    };
  }
  const ok = verifyHash(headBlockMerkleRoot, proof.block_proof, blockHash);
  return {
    name: "block is committed by the trusted head's block_merkle_root",
    ok,
    detail: `${proof.block_proof.length} path steps`,
  };
}

export { b58decode };
