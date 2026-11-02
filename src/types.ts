/** A single verification assertion, surfaced to users. */
export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

/**
 * How much a verdict can be trusted — see `trust.ts`.
 *
 * - `anchored`: approvals checked against a pinned validator set (>2/3 of real stake needed to lie)
 * - `quorum`: independent RPCs agreed on the block; safe unless every provider colludes
 * - `rpc-asserted`: one RPC supplied both the block and the validator set (self-consistent only)
 */
export type TrustLevel = "anchored" | "quorum" | "rpc-asserted";

export interface ValidatorStake {
  account_id: string;
  public_key: string;
  stake: string;
}

/** `LightClientBlockView` as returned by `next_light_client_block`. */
export interface LightClientBlockView {
  prev_block_hash: string;
  next_block_inner_hash: string;
  inner_lite: {
    height: number;
    epoch_id: string;
    next_epoch_id: string;
    prev_state_root: string;
    outcome_root: string;
    timestamp: number;
    timestamp_nanosec?: string;
    next_bp_hash: string;
    block_merkle_root: string;
  };
  inner_rest_hash: string;
  next_bps: ValidatorStake[] | null;
  approvals_after_next: (string | null)[];
}

/** `LightClientBlockLiteView` — everything needed to recompute one block hash. */
export interface LightClientBlockLiteView {
  inner_lite: LightClientBlockView["inner_lite"];
  inner_rest_hash: string;
  prev_block_hash: string;
}

export interface VerifiedLightClientHead {
  blockHash: Uint8Array;
  height: number;
  epochId: string;
  blockMerkleRoot: Uint8Array;
  outcomeRoot: Uint8Array;
  approvedStakePercent: number;
  signatureCount: number;
  checks: Check[];
}

export interface ExecutionOutcomeView {
  logs: (string | { Hash: string } | { Len: number })[];
  receipt_ids: string[];
  gas_burnt: number;
  tokens_burnt: string;
  executor_id: string;
  status: { SuccessValue?: string; SuccessReceiptId?: string; Failure?: unknown };
}

export interface ExecutionOutcomeWithIdView {
  proof: import("./merkle.js").MerklePath;
  block_hash: string;
  id: string;
  outcome: ExecutionOutcomeView;
}

/** `EXPERIMENTAL_light_client_proof` response. */
export interface LightClientProof {
  outcome_proof: ExecutionOutcomeWithIdView;
  outcome_root_proof: import("./merkle.js").MerklePath;
  block_header_lite: LightClientBlockLiteView;
  block_proof: import("./merkle.js").MerklePath;
}

export interface ProvenResult<T> {
  verified: boolean;
  value: T;
  checks: Check[];
  trust: TrustLevel;
  notes: string[];
  head: { height: number; blockHash: string; approvedStakePercent: number };
}
