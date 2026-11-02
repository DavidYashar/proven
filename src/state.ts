import { b58decode } from "./base58.js";
import { equalBytes, sha256 } from "./borsh.js";
import { bytesToHex, bytesToUtf8, base64ToBytes } from "./bytes.js";
import { authenticateBlockRoots } from "./block-header.js";
import { NearRpc } from "./rpc.js";
import { resolveHead, type ResolveHeadOptions, type ResolvedHead } from "./trust.js";
import { contractDataKey, valueMatchesRef, verifyStateProof } from "./trie.js";
import type { Check, ProvenResult, TrustLevel } from "./types.js";

/**
 * Contract-storage proofs.
 *
 * The trie proof binds the *value* to a *state root*: the RPC cannot hand back a different value
 * without breaking the path, because every node on the way is sha256-addressed and the leaf commits
 * to `sha256(value)`.
 *
 * What is **not** yet anchored: the state root itself. NEAR's RPC exposes no proof for a chunk
 * header, so binding `prev_state_root` to the light client head would require re-encoding
 * `BlockHeaderInnerRest` and `ShardChunkHeader` (both protocol-versioned). Until that lands, the
 * trust level is `quorum` (independent RPCs agree on the root) or `rpc-asserted`, never `anchored`.
 */
export interface ContractStateOptions extends Omit<ResolveHeadOptions, "rpcs"> {
  rpc?: string | NearRpc;
  rpcs?: Array<string | NearRpc>;
}

export interface ContractStateValue {
  accountId: string;
  /** the storage key, as read from the chain */
  key: Uint8Array;
  /** value bytes, or null when the key is absent */
  value: Uint8Array | null;
  valueText: string | null;
  /** state root the proof folds to */
  stateRoot: string;
  /** shard whose `prev_state_root` equals that root, when it can be located */
  shard: number | null;
  /** block whose chunk headers were used to locate the shard */
  rootBlockHeight: number;
  queryBlockHeight: number;
  proofNodes: number;
}

const DEFAULT_RPC = "https://free.rpc.fastnear.com";

const asRpc = (rpc: string | NearRpc): NearRpc => (rpc instanceof NearRpc ? rpc : new NearRpc(rpc));

export async function verifyContractState(
  accountId: string,
  key: Uint8Array,
  options: ContractStateOptions = {},
): Promise<ProvenResult<ContractStateValue>> {
  const rpcs = (options.rpcs?.length ? options.rpcs : [options.rpc ?? DEFAULT_RPC]).map(asRpc);
  const resolved = await resolveHead({
    rpcs,
    checkpoint: options.checkpoint,
    requireAnchor: options.requireAnchor,
    anchorDepth: options.anchorDepth,
  });
  const checks: Check[] = [...resolved.checks];
  const notes: string[] = [...resolved.notes];

  // The post-state of block H is committed as the chunk's `prev_state_root` in block H+1, so query
  // one block behind the head and look for the root in the head's chunk headers.
  const queryHeight = Math.max(1, resolved.head.height - 1);
  const trieKey = contractDataKey(accountId, key);

  interface Attempt {
    url: string;
    root: string;
    found: boolean;
    value: Uint8Array | null;
    proofNodes: number;
    valueRef: { length: number; hash: Uint8Array } | null;
  }
  const attempts: Attempt[] = [];

  for (const rpc of rpcs) {
    try {
      const response = await rpc.viewStateWithProof(accountId, queryHeight, key);
      const proof: Uint8Array[] = (response.proof ?? []).map((p: string) => base64ToBytes(p));
      if (proof.length === 0) throw new Error("node returned no state proof");
      const result = verifyStateProof(proof, trieKey);
      const raw = (response.values ?? [])[0];
      const value = raw ? base64ToBytes(raw.value) : null;

      attempts.push({
        url: rpc.url,
        root: bytesToHex(result.root),
        found: result.found,
        value,
        proofNodes: proof.length,
        valueRef: result.found ? { length: result.valueLength!, hash: result.valueHash! } : null,
      });
    } catch (error) {
      notes.push(`${rpc.url}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (attempts.length === 0) {
    throw new Error(`no RPC could produce a verifiable state proof (${notes.join("; ")})`);
  }

  const chosen = attempts[0];
  if (chosen.valueRef) {
    const matches = chosen.value !== null && valueMatchesRef(chosen.value, chosen.valueRef);
    checks.push({
      name: "stored value matches the leaf's commitment",
      ok: matches,
      detail: `${chosen.value?.length ?? 0} bytes of ${chosen.valueRef.length} committed`,
    });
  } else {
    checks.push({ name: "key is absent from the trie (proven by the path)", ok: true });
  }

  // Anchor the state root: reproduce the head block's header commitments, which the light client
  // block already authenticated, and require the proof to fold to one of the resulting roots.
  let shard: number | null = null;
  let rootBlockHeight = queryHeight;
  let anchored = false;
  try {
    // Any provider may serve the block: the roots are checked against the signed light client
    // block, so a fallback node cannot bias the result.
    let block: any;
    const errors: string[] = [];
    for (const rpc of rpcs) {
      try {
        block = await rpc.block(queryHeight + 1);
        break;
      } catch (error) {
        errors.push(`${rpc.url}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    if (!block) throw new Error(`no RPC served block ${queryHeight + 1} (${errors.join("; ")})`);

    const roots = authenticateBlockRoots(block, resolved.view);
    checks.push(...roots.checks);
    rootBlockHeight = Number(block.header.height);

    const matched = [...roots.stateRoots.entries()].find(
      ([, root]) => bytesToHex(b58decode(root)) === chosen.root,
    );
    shard = matched ? matched[0] : null;
    // What the cryptography says: the value folds into a root this block's chunk headers commit to.
    // Whether that block is itself anchored is a *trust* question, reported separately — a weak pin
    // must never turn a valid proof into a failed one.
    const folded = shard !== null && roots.checks.every((c) => c.ok);
    anchored = folded && resolved.trust === "anchored";
    checks.push({
      name: "proof folds to a state root committed by the head's chunk headers",
      ok: folded,
      detail:
        shard === null
          ? "root is not among the head's authenticated chunk state roots"
          : `shard ${shard}, block ${rootBlockHeight}`,
    });
  } catch (error) {
    notes.push(`could not authenticate the block header: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Independent nodes must agree on both the root and the value, which catches a provider that
  // answers with someone else's data. Anchoring is what decides `anchored` below.
  let trust: TrustLevel = "rpc-asserted";
  if (attempts.length > 1) {
    const [first, ...rest] = attempts;
    const agree = rest.every(
      (a) =>
        a.root === first.root &&
        a.found === first.found &&
        (a.value === null || first.value === null
          ? a.value === first.value
          : equalBytes(a.value, first.value)),
    );
    checks.push({
      name: `${attempts.length} independent RPCs agree on the value and its proof`,
      ok: agree,
      detail: agree ? `state root ${first.root.slice(0, 12)}â€¦` : "nodes disagree",
    });
    trust = agree ? "quorum" : "rpc-asserted";
  }

  // Locate the shard whose chunk header commits to this root.
  if (anchored) trust = "anchored";
  else {
    notes.push(
      resolved.trust === "anchored"
        ? "the header layout did not match this protocol version, so the state root is not anchored"
        : `state root reached a chunk header, but that block is not anchored (trust is ${resolved.trust}: no pin covers this epoch — run \`proven checkpoint\`)`,
    );
  }

  const value = chosen.value;
  return {
    verified: checks.every((c) => c.ok),
    value: {
      accountId,
      key,
      value,
      valueText: value ? printable(value) : null,
      stateRoot: chosen.root,
      shard,
      rootBlockHeight,
      queryBlockHeight: queryHeight,
      proofNodes: chosen.proofNodes,
    },
    checks,
    trust,
    notes,
    head: {
      height: resolved.head.height,
      blockHash: bytesToHex(resolved.head.blockHash),
      approvedStakePercent: resolved.head.approvedStakePercent,
    },
  };
}

/** Storage values are often JSON or plain text; show it when it round-trips. */
function printable(bytes: Uint8Array): string {
  const text = bytesToUtf8(bytes);
  // eslint-disable-next-line no-control-regex
  return /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text) ? text : `${bytesToHex(bytes).slice(0, 64)}â€¦`;
}

export { sha256 };

