import { b58encode } from "./base58.js";
import { sha256 } from "./borsh.js";
import { borshValidatorStakes, lightClientBlockHash } from "./light-client.js";
import type { LightClientBlockView, ValidatorStake } from "./types.js";

/**
 * A pinned set of block producers.
 *
 * Without one, the validator set that signs a head is supplied by the same RPC that serves the head —
 * self-consistent, but a hostile endpoint could invent an entire validator set and sign with it.
 * Pinning the producers of an epoch removes that: an attacker would need the private keys of >2/3 of
 * NEAR's real stake.
 *
 * The pinned validators are the ones that sign blocks **in `epochId`**, i.e. the `next_bps` of the
 * view from the *previous* epoch (see `fetchSignerSet`). Anchoring is then a signature check, not a
 * hash comparison: >2/3 of this pinned stake must have signed the head.
 *
 * A pin is only valid while the network is still in `epochId` (epochs are ~12h), so `proven
 * checkpoint` regenerates it and `proven` falls back to weaker trust levels when it is stale rather
 * than silently pretending to be anchored.
 */
export interface Checkpoint {
  /** Format marker: v2 pins the epoch's *signing* set. v1 pinned the next epoch's set by mistake. */
  version: 2;
  network: string;
  /** Epoch these producers sign for. */
  epochId: string;
  nextEpochId?: string;
  /** Height of the head this checkpoint was taken at. */
  height: number;
  blockHash: string;
  /** Producers of `epochId`, in the order the node reported them. */
  validators: ValidatorStake[];
  /** base58 sha256(borsh(validators)) — integrity check for the file itself. */
  validatorsHash: string;
  capturedAt?: string;
  sourceRpc?: string;
}

/** `sha256(borsh(Vec<ValidatorStakeView>))`, base58 — how nearcore commits to a producer set. */
export const validatorsHash = (validators: readonly ValidatorStake[]): string =>
  b58encode(sha256(borshValidatorStakes(validators)));

export function makeCheckpoint(
  view: LightClientBlockView,
  signers: readonly ValidatorStake[],
  options: { network?: string; sourceRpc?: string } = {},
): Checkpoint {
  if (signers.length === 0) {
    throw new Error(`no producer set supplied for epoch ${view.inner_lite.epoch_id.slice(0, 8)}…; cannot build a checkpoint`);
  }
  return {
    version: 2,
    network: options.network ?? "mainnet",
    epochId: view.inner_lite.epoch_id,
    nextEpochId: view.inner_lite.next_epoch_id,
    height: view.inner_lite.height,
    blockHash: b58encode(lightClientBlockHash(view)),
    validators: [...signers],
    validatorsHash: validatorsHash(signers),
    capturedAt: new Date().toISOString(),
    sourceRpc: options.sourceRpc,
  };
}

/** Parses and self-checks a checkpoint (its stored hash must match its validators). */
export function parseCheckpoint(input: string | Checkpoint): Checkpoint {
  const parsed: Checkpoint = typeof input === "string" ? JSON.parse(input) : input;
  for (const field of ["epochId", "blockHash", "validatorsHash"] as const) {
    if (typeof parsed[field] !== "string") throw new Error(`checkpoint is missing "${field}"`);
  }
  if (!Array.isArray(parsed.validators) || parsed.validators.length === 0) {
    throw new Error("checkpoint is missing its validator set");
  }
  if (parsed.version !== 2) {
    throw new Error(
      "this checkpoint predates the v2 format, which pins the producers that actually sign the epoch; run `proven checkpoint` to re-pin",
    );
  }
  const recomputed = validatorsHash(parsed.validators);
  if (recomputed !== parsed.validatorsHash) {
    throw new Error(`checkpoint is corrupt: validatorsHash is ${parsed.validatorsHash} but its validators hash to ${recomputed}`);
  }
  return parsed;
}

/** Why a checkpoint could not be used, or `null` if it covers this head's epoch. */
export function checkpointMismatch(checkpoint: Checkpoint, view: LightClientBlockView): string | null {
  if (checkpoint.epochId !== view.inner_lite.epoch_id) {
    return `checkpoint covers epoch ${checkpoint.epochId.slice(0, 8)}… but the head is in ${view.inner_lite.epoch_id.slice(0, 8)}… (stale checkpoint)`;
  }
  // Matching epochs is all that can be checked by equality: the pin holds the *signing* set, while
  // the view carries the *next* epoch's set. Whether the pin is real is settled by the signature
  // check that follows, which is stronger than comparing hashes.
  return null;
}
