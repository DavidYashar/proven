import { bridgeCheckpoint, checkpointMismatch, type Checkpoint } from "./checkpoint.js";
import { verifyLightClientBlock } from "./light-client.js";
import { NearRpc } from "./rpc.js";
import { b58encode } from "./base58.js";
import type {
  Check,
  LightClientBlockView,
  TrustLevel,
  ValidatorStake,
  VerifiedLightClientHead,
} from "./types.js";

/**
 * How much the verdict can be trusted:
 *
 * - `anchored`   — approvals verified against a **pinned** validator set (or a chain of sets
 *                  descending from one). A hostile RPC would need >2/3 of real stake to lie.
 * - `quorum`     — several independent RPCs returned byte-identical light client blocks, and
 *                  approvals were verified against the set they agree on. Safe unless every
 *                  provider colludes.
 * - `rpc-asserted` — one RPC supplied both the head and the validator set: the data is internally
 *                  consistent, but a malicious endpoint could have invented the whole chain.
 */

export interface ResolveHeadOptions {
  /** One or more RPC endpoints. Two or more enables `quorum`. */
  rpcs: Array<string | NearRpc>;
  /** Pinned checkpoint; enables `anchored`. */
  checkpoint?: Checkpoint;
  /** Fail instead of falling back when the checkpoint does not apply. */
  requireAnchor?: boolean;
  /** How far behind the final head to anchor the request. */
  anchorDepth?: number;
}

export interface ResolvedHead {
  head: VerifiedLightClientHead;
  view: LightClientBlockView;
  trust: TrustLevel;
  signers: ValidatorStake[];
  /** Where the signer set came from — shown to the user, because it is the whole trust argument. */
  signerSource: string;
  checks: Check[];
  /** Non-fatal remarks (e.g. "checkpoint is stale, fell back to quorum"). */
  notes: string[];
  /**
   * A pin that was walked forward to cover this head. Callers should adopt and persist it: otherwise
   * every request re-walks the same gap.
   */
  bridgedPin?: Checkpoint;
  /**
   * The producer set for the *next* epoch, when this head was verified against a pin. It is committed
   * by this header's `next_bp_hash` and the header itself was signed by the pinned set, so adopting it
   * advances the pin without trusting the endpoint. A caller that checks in once per epoch can stay
   * `anchored` forever.
   */
  nextPin?: { epochId: string; validators: ValidatorStake[] };
}

const asRpc = (rpc: string | NearRpc): NearRpc => (rpc instanceof NearRpc ? rpc : new NearRpc(rpc));

/** NEAR epochs are 43,200 blocks (~7h at ~0.57s/block). */
const EPOCH_BLOCKS = 43_200;

/**
 * The keys that sign a block in epoch `targetEpochId` are the `next_bps` of a view from the
 * **previous** epoch — `next_bps` is the set for the epoch *after* the view's own.
 *
 * A fresh client has no previous view, and `next_light_client_block` never steps back one epoch at
 * a time (it returns the latest view, or one as much as ~60k blocks past the anchor). So probe
 * anchors across the previous epoch and steer by the epoch ids the views report. Every candidate is
 * checked cryptographically afterwards, so a wrong guess can only cost a failed verification —
 * never a false accept.
 */
export async function fetchSignerSet(
  rpc: NearRpc,
  targetEpochId: string,
  referenceHeight: number,
): Promise<ValidatorStake[] | null> {
  const step = EPOCH_BLOCKS / 2;
  let depth = EPOCH_BLOCKS + 59_000;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const anchor = await rpc.block(Math.max(1, referenceHeight - depth));
      const view = (await rpc.nextLightClientBlock(anchor.header.hash)) as LightClientBlockView | null;
      if (view?.inner_lite && view.next_bps?.length) {
        if (view.inner_lite.next_epoch_id === targetEpochId) return view.next_bps;
        // In the target epoch → its next_bps is one too new. Older than the previous epoch → come forward.
        depth = view.inner_lite.epoch_id === targetEpochId ? depth + step : Math.max(step, depth - step);
      } else {
        depth += step;
      }
    } catch {
      depth += step;
    }
  }
  return null;
}

/** Fetches a light client block, preferring one whose block is already final. */
export async function fetchLightClientBlock(rpc: NearRpc, anchorDepth = 3): Promise<LightClientBlockView> {
  let lastError: Error | undefined;
  let best: LightClientBlockView | undefined;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const final = await rpc.finalBlock();
      const finalHeight = Number(final.header.height);
      const anchorHeight = Math.max(1, finalHeight - anchorDepth);
      const anchor = await rpc.block(anchorHeight);
      const view = (await rpc.nextLightClientBlock(anchor.header.hash)) as LightClientBlockView | null;
      if (!view?.inner_lite) {
        lastError = new Error("RPC returned no light client block (node may still be syncing)");
      } else if (Number(view.inner_lite.height) <= finalHeight) {
        return view;
      } else {
        // The node offered a block a little past the head it reports as final. Nodes disagree about
        // where finality sits by a block or two; wait briefly, then accept it — the approvals in the
        // view are what authenticate it, and the caller still checks it is the canonical block.
        best = view;
        lastError = new Error(
          `light client block ${view.inner_lite.height} is ahead of the final head ${finalHeight}`,
        );
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
    if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 1200));
  }
  if (best) return best;
  throw lastError ?? new Error("could not obtain a light client block");
}

/** Fingerprint of the fields that define a light client block, for cross-provider comparison. */
const fingerprint = (view: LightClientBlockView): string =>
  JSON.stringify([view.inner_lite, view.inner_rest_hash, view.prev_block_hash, view.next_bps]);

export async function resolveHead(options: ResolveHeadOptions): Promise<ResolvedHead> {
  if (!options.rpcs?.length) throw new Error("resolveHead needs at least one RPC");
  const rpcs = options.rpcs.map(asRpc);
  const settled = await Promise.allSettled(
    rpcs.map((rpc) => fetchLightClientBlock(rpc, options.anchorDepth ?? 3)),
  );

  const notes: string[] = [];
  const checks: Check[] = [];

  const views: LightClientBlockView[] = [];
  settled.forEach((result, index) => {
    if (result.status === "fulfilled") {
      views.push(result.value);
    } else {
      const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
      notes.push(`${rpcs[index].url} did not serve a light client block: ${reason}`);
    }
  });
  if (views.length === 0) {
    throw new Error(`no RPC could serve a light client block (${notes.join("; ")})`);
  }

  // 1. Providers can legitimately be a block apart, so compare only views that claim the same
  //    height: two different descriptions of one height is a contradiction, timing skew is not.
  let quorum = false;
  // The head we verify must be the one the providers corroborated — not simply the first to answer.
  let view = views[0];
  if (views.length > 1) {
    const byHeight = new Map<number, LightClientBlockView[]>();
    for (const candidate of views) {
      const height = Number(candidate.inner_lite.height);
      byHeight.set(height, [...(byHeight.get(height) ?? []), candidate]);
    }
    const comparable = [...byHeight.values()].filter((group) => group.length > 1);
    if (comparable.length === 0) {
      notes.push(
        `providers are at different heights (${[...byHeight.keys()].sort((a, b) => a - b).join(", ")}); quorum not established`,
      );
    } else {
      const contradictions = comparable.filter(
        (group) => group.some((candidate) => fingerprint(candidate) !== fingerprint(group[0])),
      ).length;
      quorum = contradictions === 0;
      // Use a head from the largest agreeing group; a lone provider at another height must not
      // become the head the verdict is computed against.
      const largest = [...comparable].sort((a, b) => b.length - a.length)[0];
      view = largest[0];
      checks.push({
        name: "independent RPCs agree on the same light client block",
        ok: quorum,
        detail: quorum
          ? `${largest.length} providers at height ${largest[0].inner_lite.height}`
          : `${contradictions} contradiction(s) — at least one provider is lying`,
      });
    }
  }
  const rpcValidators = view.next_bps ?? [];
  const epochId = view.inner_lite.epoch_id;

  // 2. Decide which validator set is allowed to authenticate this head.
  let signers: ValidatorStake[] | null = null;
  let bridgedPin: Checkpoint | undefined;
  let signerSource = "";
  let trust: TrustLevel = quorum ? "quorum" : "rpc-asserted";

  if (options.checkpoint) {
    let pin = options.checkpoint;
    let mismatch = checkpointMismatch(pin, view);
    if (mismatch !== null && (pin.version ?? 0) >= 3) {
      // The pin is stale, but it can be walked forward: each epoch's producer set is committed by the
      // previous epoch's signed header. Recovering here is what keeps a shipped pin usable days later.
      // Every provider gets a turn, because a pruned endpoint drops old blocks while an archival one
      // keeps them ? and this runs in strict mode too, since a walked pin is fully signature-checked.
      let bridged: Awaited<ReturnType<typeof bridgeCheckpoint>> = null;
      for (const rpc of rpcs) {
        bridged = await bridgeCheckpoint(rpc, pin, epochId).catch(() => null);
        if (bridged) break;
      }
      if (bridged) {
        pin = bridged.checkpoint;
        bridgedPin = bridged.checkpoint;
        mismatch = checkpointMismatch(pin, view);
        notes.push(
          `stale pin walked forward ${bridged.steps} epoch(s) (${options.checkpoint.epochId.slice(0, 8)}… -> ${pin.epochId.slice(0, 8)}…), each step signed by the set the previous one committed to`,
        );
      }
    }
    if (mismatch === null) {
      signers = pin.validators;
      signerSource = "pinned checkpoint";
      trust = "anchored";
      checks.push({
        name: "checkpoint applies to this head",
        ok: true,
        detail: `epoch ${epochId.slice(0, 8)}…, ${signers.length} pinned producers`,
      });
    } else if (options.requireAnchor) {
      checks.push({ name: "checkpoint applies to this head", ok: false, detail: mismatch });
    } else {
      notes.push(`${mismatch} — falling back to ${trust}`);
    }
  } else if (options.requireAnchor) {
    checks.push({ name: "checkpoint applies to this head", ok: false, detail: "no checkpoint supplied" });
  }

  if (!signers) {
    // No usable pin: fetch the set that actually signed this epoch rather than trusting the one the
    // response carries (`view.next_bps` belongs to the *next* epoch, so verifying against it silently
    // drops every validator whose position moved at the boundary). Any provider may answer — a wrong
    // set only makes verification fail, so one dead endpoint must not block the others.
    let fetched: ValidatorStake[] | null = null;
    for (const rpc of rpcs) {
      fetched = await fetchSignerSet(rpc, epochId, Number(view.inner_lite.height)).catch(() => null);
      if (fetched) break;
    }
    if (fetched) {
      signers = fetched;
      signerSource = "previous epoch's producer set, fetched from the chain";
    } else {
      signers = rpcValidators;
      signerSource = "the response's own next_bps (approximate — one epoch ahead)";
      notes.push(
        "could not obtain the producer set that signed this epoch; approvals were checked against the next epoch's set, so the approved stake is under-counted",
      );
    }
  }

  // 3. Verify the head with the chosen signer set.
  const head = verifyLightClientBlock(view, { validators: signers });
  checks.push(...head.checks);

  // 4. Sanity: the block we verified is the canonical block at its height. Any provider may answer
  // — the comparison is against the hash we already verified, so a lie here shows up as a mismatch.
  const canonicalErrors: string[] = [];
  let canonicalHash: string | null = null;
  for (const rpc of rpcs) {
    try {
      canonicalHash = (await rpc.block(head.height)).header.hash;
      break;
    } catch (error) {
      canonicalErrors.push(`${rpc.url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  checks.push(
    canonicalHash === null
      ? {
          name: "verified head is the canonical block at its height",
          ok: false,
          detail: `no RPC served block ${head.height} (${canonicalErrors.join("; ")})`,
        }
      : {
          name: "verified head is the canonical block at its height",
          ok: canonicalHash === b58encode(head.blockHash),
          detail: `height ${head.height}`,
        },
  );

  // If the pin authenticated this head, the header also commits to the *next* epoch's producers.
  // Adopting them is what keeps a long-running verifier anchored across epoch boundaries, without
  // ever taking a set from the endpoint unverified: `next_bp_hash` is inside the signed header.
  const canRoll =
    trust === "anchored" &&
    checks.every((c) => c.ok) &&
    (view.next_bps?.length ?? 0) > 0 &&
    view.inner_lite.next_epoch_id !== epochId;
  const nextPin = canRoll
    ? { epochId: view.inner_lite.next_epoch_id, validators: view.next_bps as ValidatorStake[] }
    : undefined;

  return { head, view, trust, signers, signerSource, checks, notes, nextPin, bridgedPin };
}