import { b58decode, b58encode } from "./base58.js";
import { base64ToBytes, bytesToUtf8 } from "./bytes.js";
import { lightClientBlockHash } from "./light-client.js";
import { verifyBlockInclusion, verifyOutcomeRoot } from "./outcome.js";
import { NearRpc } from "./rpc.js";
import { resolveHead, type ResolveHeadOptions, type ResolvedHead } from "./trust.js";
import type { Check, LightClientProof, ProvenResult } from "./types.js";

export interface VerifyOptions {
  /** A single RPC. A malicious one can make verification fail, or force a weaker trust level. */
  rpc?: string | NearRpc;
  /** Several RPCs: two or more enables `quorum` trust. */
  rpcs?: Array<string | NearRpc>;
  /** Pinned checkpoint (`proven checkpoint` output); enables `anchored` trust. */
  checkpoint?: ResolveHeadOptions["checkpoint"];
  /** Fail instead of silently falling back when the checkpoint does not apply. */
  requireAnchor?: boolean;
  /** How many blocks behind the final head to anchor the light client block request. */
  anchorDepth?: number;
  /**
   * A head that was already resolved (and verified) by the caller. Serving many proofs in a row is
   * the normal case — a proxy or an indexer — and re-resolving the head per request multiplies the
   * RPC traffic by six. Reusing one head costs nothing in trust: it is the same authority the proof
   * is checked against, and a caller that resolves it once has already paid for it.
   */
  resolvedHead?: ResolvedHead;
}

export interface ProvenOutcome {
  outcome: LightClientProof["outcome_proof"]["outcome"];
  /** height of the block that contains the outcome */
  height: number;
  blockHash: string;
  /** raw proof payload, so callers can re-verify or store it */
  proof: LightClientProof;
}

const DEFAULT_RPC = "https://free.rpc.fastnear.com";

function resolveOptions(options: VerifyOptions): ResolveHeadOptions {
  const rpcs = options.rpcs?.length ? options.rpcs : [options.rpc ?? DEFAULT_RPC];
  return {
    rpcs,
    checkpoint: options.checkpoint,
    requireAnchor: options.requireAnchor,
    anchorDepth: options.anchorDepth,
  };
}

/**
 * Tries each provider in turn until one serves a proof. The proof is verified afterwards, so taking
 * it from whichever node answers costs no trust — and a dead endpoint cannot stop verification.
 */
async function firstProof<T>(options: VerifyOptions, fetchProof: (rpc: NearRpc) => Promise<T>): Promise<T> {
  const candidates = (options.rpcs?.length ? options.rpcs : [options.rpc ?? DEFAULT_RPC]).map((rpc) =>
    rpc instanceof NearRpc ? rpc : new NearRpc(rpc),
  );
  const reasons: string[] = [];
  for (const rpc of candidates) {
    try {
      return await fetchProof(rpc);
    } catch (error) {
      reasons.push(`${rpc.url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`no RPC served a proof (${reasons.join("; ")})`);
}

/** Verifies a proof payload against a resolved head, returning the full check list. */
function verifyAgainstHead(
  resolved: ResolvedHead,
  proof: LightClientProof,
  expectation: Check,
): { checks: Check[]; verified: boolean } {
  const proofBlockHash = lightClientBlockHash(proof.block_header_lite);
  const checks: Check[] = [...resolved.checks, expectation];

  checks.push({
    name: "proof's block header recomputes to the outcome's block_hash",
    ok: b58encode(proofBlockHash) === proof.outcome_proof.block_hash,
  });

  // The outcome is committed by the outcome_root of the block that contains it; that block is in
  // turn committed by the trusted head's block_merkle_root (checked below).
  const outcome = verifyOutcomeRoot(proof, b58decode(proof.block_header_lite.inner_lite.outcome_root));
  checks.push(...outcome.checks);
  checks.push(verifyBlockInclusion(proof, proofBlockHash, resolved.head.blockMerkleRoot, resolved.head.blockHash));

  return { checks, verified: checks.every((c) => c.ok) };
}

function build<T>(resolved: ResolvedHead, checks: Check[], verified: boolean, value: T): ProvenResult<T> {
  return {
    verified,
    value,
    checks,
    trust: resolved.trust,
    notes: resolved.notes,
    head: {
      height: resolved.head.height,
      blockHash: b58encode(resolved.head.blockHash),
      approvedStakePercent: resolved.head.approvedStakePercent,
    },
  };
}

/** Verifies a transaction's execution outcome end-to-end. */
export async function verifyTransaction(
  transactionHash: string,
  senderId: string,
  options: VerifyOptions = {},
): Promise<ProvenResult<ProvenOutcome>> {
  const resolved = options.resolvedHead ?? (await resolveHead(resolveOptions(options)));
  const proof = (await firstProof(options, (rpc) =>
    rpc.lightClientProofTransaction(transactionHash, senderId, b58encode(resolved.head.blockHash)),
  )) as LightClientProof;

  const { checks, verified } = verifyAgainstHead(resolved, proof, {
    name: "proof is for the requested transaction",
    ok: proof.outcome_proof.id === transactionHash,
  });

  return build(resolved, checks, verified, {
    outcome: proof.outcome_proof.outcome,
    height: proof.block_header_lite.inner_lite.height,
    blockHash: proof.outcome_proof.block_hash,
    proof,
  });
}

/** Verifies a receipt's execution outcome end-to-end (works for read-only contract calls too). */
export async function verifyReceipt(
  receiptId: string,
  receiverId: string,
  options: VerifyOptions = {},
): Promise<ProvenResult<ProvenOutcome>> {
  const resolved = options.resolvedHead ?? (await resolveHead(resolveOptions(options)));
  const proof = (await firstProof(options, (rpc) =>
    rpc.lightClientProofReceipt(receiptId, receiverId, b58encode(resolved.head.blockHash)),
  )) as LightClientProof;

  const { checks, verified } = verifyAgainstHead(resolved, proof, {
    name: "proof is for the requested receipt",
    ok: proof.outcome_proof.id === receiptId,
  });

  return build(resolved, checks, verified, {
    outcome: proof.outcome_proof.outcome,
    height: proof.block_header_lite.inner_lite.height,
    blockHash: proof.outcome_proof.block_hash,
    proof,
  });
}

/** Decodes a `SuccessValue` outcome into a printable value (`null` for other statuses). */
export function decodeSuccessValue(outcome: LightClientProof["outcome_proof"]["outcome"]): string | null {
  if (outcome.status.SuccessValue === undefined) return null;
  const text = bytesToUtf8(base64ToBytes(outcome.status.SuccessValue));
  try {
    return JSON.stringify(JSON.parse(text));
  } catch {
    return text;
  }
}

export { resolveHead };
export type { ResolvedHead };
