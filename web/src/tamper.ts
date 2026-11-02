import { b58encode } from "../../dist/base58.js";
import { base64ToBytes, bytesToBase64 } from "../../dist/bytes.js";
import { sha256 } from "../../dist/borsh.js";
import {
  approvalMessage,
  borshValidatorStakes,
  lightClientBlockHash,
  nextBlockHash,
} from "../../dist/light-client.js";
import { ed25519 } from "@noble/curves/ed25519.js";

/**
 * Hostile endpoints for the demo. Two of the attacks corrupt bytes in flight; the third does
 * something worse — it fabricates a validator set and signs with keys it owns, which produces a
 * head that passes every signature check.
 */
export type Lie = "none" | "outcome" | "finality" | "forge" | "value";

export const LIES: { value: Lie; label: string; blurb: string }[] = [
  { value: "none", label: "honest endpoint", blurb: "passes responses through untouched" },
  {
    value: "outcome",
    label: "rewrites the outcome",
    blurb: "claims the transaction was executed by a different account",
  },
  {
    value: "finality",
    label: "fakes finality",
    blurb: "strips the validator signatures so an unfinalised head looks settled",
  },
  {
    value: "forge",
    label: "forges a validator set",
    blurb: "invents 100 producers, signs with its own keys — self-consistent, but not NEAR",
  },
  {
    value: "value",
    label: "rewrites stored state",
    blurb: "returns different bytes for a contract's storage key than the trie commits to",
  },
];

const random32 = (): Uint8Array => ed25519.utils.randomSecretKey();

/** A light client block that is internally perfect and entirely made up. */
function forgeHead(prevBlockHash: string, height: number, epoch: { epochId: string; nextEpochId: string }): any {
  const secrets = Array.from({ length: 100 }, () => random32());
  const stakes = secrets.map((secret, i) => ({
    account_id: `forge-validator-${i}.near`,
    public_key: `ed25519:${b58encode(ed25519.getPublicKey(secret))}`,
    stake: "9000000000000000000000000000000",
  }));

  const view: any = {
    prev_block_hash: prevBlockHash,
    next_block_inner_hash: b58encode(random32()),
    inner_lite: {
      height,
      // The real epoch ids, so only the validator set itself gives the forgery away.
      epoch_id: epoch.epochId,
      next_epoch_id: epoch.nextEpochId,
      prev_state_root: b58encode(random32()),
      outcome_root: b58encode(random32()),
      timestamp: Date.now() * 1_000_000,
      next_bp_hash: b58encode(sha256(borshValidatorStakes(stakes))),
      block_merkle_root: b58encode(random32()),
    },
    inner_rest_hash: b58encode(random32()),
    next_bps: stakes,
    approvals_after_next: [] as (string | null)[],
  };

  const blockHash = lightClientBlockHash(view);
  const message = approvalMessage(nextBlockHash(view, blockHash), height);
  view.approvals_after_next = secrets.map((secret) => `ed25519:${b58encode(ed25519.sign(message, secret))}`);
  view.__forgedBlockHash = b58encode(blockHash);
  return view;
}

const json = (id: unknown, result: unknown): Response =>
  new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), {
    headers: { "content-type": "application/json" },
  });

/** Wraps `fetch` so that JSON-RPC answers can be tampered with before the verifier sees them. */
export function createTamperedFetch(lie: Lie, onEvent?: (message: string) => void): typeof fetch {
  let realFinalHash: string | null = null;
  let realFinalHeight = 0;
  let realEpoch: { epochId: string; nextEpochId: string } | null = null;
  let forged: any = null;

  return async (input: any, init?: any): Promise<Response> => {
    const response = await fetch(input, init);
    if (lie === "none") return response;

    let request: any = {};
    try {
      request = JSON.parse(String(init?.body ?? "{}"));
    } catch {
      return response;
    }
    const body = await response.clone().json().catch(() => null);
    if (!body || body.error) return response;
    const { method, params } = request;

    if (lie === "forge") {
      if (method === "block" && params?.finality) {
        realFinalHash = body.result?.header?.hash ?? null;
        realFinalHeight = Number(body.result?.header?.height ?? 0);
        realEpoch = {
          epochId: body.result?.header?.epoch_id ?? "",
          nextEpochId: body.result?.header?.next_epoch_id ?? body.result?.header?.epoch_id ?? "",
        };
        return response;
      }
      if (method === "next_light_client_block") {
        if (!realFinalHash || !realEpoch) return response;
        forged = forged ?? forgeHead(realFinalHash, realFinalHeight, realEpoch);
        onEvent?.(`forged head ${forged.inner_lite.height} signed by 100 attacker validators`);
        return json(body.id, forged);
      }
      if (method === "block" && forged && params?.block_id !== undefined) {
        // Keep the "is this the canonical block at that height?" check consistent with the lie.
        return json(body.id, { header: { height: forged.inner_lite.height, hash: forged.__forgedBlockHash } });
      }
      return response;
    }

    if (lie === "finality" && method === "next_light_client_block" && body.result?.inner_lite) {
      onEvent?.("validator signatures stripped from the light client block");
      return json(body.id, {
        ...body.result,
        approvals_after_next: (body.result.approvals_after_next ?? []).map(() => null),
      });
    }

    if (lie === "outcome" && /light_client_proof/.test(method) && body.result?.outcome_proof?.outcome) {
      onEvent?.("outcome rewritten: executor_id replaced");
      const outcome = body.result.outcome_proof.outcome;
      return json(body.id, {
        ...body.result,
        outcome_proof: {
          ...body.result.outcome_proof,
          outcome: { ...outcome, executor_id: `${outcome.executor_id}-attacker` },
        },
      });
    }

    if (lie === "value" && method === "query" && Array.isArray(body.result?.values) && body.result.values.length) {
      // Keep the proof, rewrite the bytes the caller will read: exactly the lie a trie cannot support.
      const [first, ...rest] = body.result.values;
      const tampered = base64ToBytes(first.value);
      tampered[tampered.length - 1] ^= 0xff;
      onEvent?.("stored value rewritten (proof left untouched)");
      return json(body.id, {
        ...body.result,
        values: [{ ...first, value: bytesToBase64(tampered) }, ...rest],
      });
    }

    return response;
  };
}
