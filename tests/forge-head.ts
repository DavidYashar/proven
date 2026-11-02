// The attack checkpoints exist for: an RPC invents its own validator set, signs a fake head with
// keys it controls, and serves it as final.
//
//   npx tsx tests/forge-head.ts
//
// Without a pinned checkpoint the forgery is *internally consistent* — every signature verifies,
// the validator-set hash matches the header — so the tool reports `rpc-asserted` rather than
// claiming more than it knows. With a pinned checkpoint the same response is rejected outright.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";

import { b58decode, b58encode } from "../src/base58.js";
import { sha256 } from "../src/borsh.js";
import { parseCheckpoint, type Checkpoint } from "../src/checkpoint.js";
import {
  approvalMessage,
  borshValidatorStakes,
  lightClientBlockHash,
  nextBlockHash,
} from "../src/light-client.js";
import { resolveHead } from "../src/trust.js";
import type { LightClientBlockView, ValidatorStake } from "../src/types.js";

const random32 = (): Uint8Array => ed25519.utils.randomSecretKey();

/** Three colluding validators with implausible stake, controlled by the liar. */
function forgeValidators(count = 3): { stakes: ValidatorStake[]; secrets: Uint8Array[] } {
  const secrets = Array.from({ length: count }, () => random32());
  const stakes = secrets.map((secret, i) => ({
    account_id: `forge-validator-${i}.near`,
    public_key: `ed25519:${b58encode(ed25519.getPublicKey(secret))}`,
    stake: "900000000000000000000000000000000", // 900M NEAR each
  }));
  return { stakes, secrets };
}

/** Builds a light client block that is self-consistent but entirely fabricated. */
export function forgeHead(
  prevBlockHash: string,
  height: number,
  epoch: { epochId: string; nextEpochId: string },
): LightClientBlockView {
  const { stakes, secrets } = forgeValidators();
  const view: LightClientBlockView = {
    prev_block_hash: prevBlockHash,
    next_block_inner_hash: b58encode(random32()),
    inner_lite: {
      height,
      // Reuses the real epoch ids, so the epoch alone cannot give the forgery away.
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
    approvals_after_next: [],
  };

  const blockHash = lightClientBlockHash(view);
  const message = approvalMessage(nextBlockHash(view, blockHash), height);
  view.approvals_after_next = secrets.map((secret) => `ed25519:${b58encode(ed25519.sign(message, secret))}`);
  return view;
}

/** Minimal JSON-RPC surface that serves one forged head and nothing else. */
function startForgeNode(view: LightClientBlockView, realFinalHash: string): Promise<{ url: string; close: () => void }> {
  const forgedHash = b58encode(lightClientBlockHash(view));
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const { method, params } = JSON.parse(raw || "{}");
      const send = (result: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: "1", result }));
      };
      if (method === "block" && params?.finality) {
        return send({ header: { height: view.inner_lite.height, hash: realFinalHash } });
      }
      if (method === "block" && params?.block_id !== undefined) {
        return send({ header: { height: view.inner_lite.height, hash: forgedHash } });
      }
      if (method === "next_light_client_block") {
        return send(view);
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: "1", error: { message: "not implemented by the liar" } }));
    });
  });
  return new Promise((resolve) =>
    server.listen(8799, "127.0.0.1", () => resolve({ url: "http://127.0.0.1:8799", close: () => server.close() })),
  );
}

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

async function main() {
  const checkpoint = parseCheckpoint(
    readFileSync(new URL("../checkpoints/mainnet.json", import.meta.url), "utf8") as unknown as string,
  ) as Checkpoint;

  // A hash the liar can point at as "the real chain"; the forgery extends it. The forged head
  // claims the same epoch as the checkpoint, so only the validator set itself exposes it.
  const realFinalHash = checkpoint.blockHash;
  const view = forgeHead(realFinalHash, checkpoint.height + 1, {
    epochId: checkpoint.epochId,
    nextEpochId: checkpoint.nextEpochId ?? checkpoint.epochId,
  });
  const node = await startForgeNode(view, realFinalHash);

  try {
    console.log(`${DIM}rpc: ${node.url} (forged head ${view.inner_lite.height})${RESET}\n`);

    const naive = await resolveHead({ rpcs: [node.url] });
    console.log(`no checkpoint        → trust ${YELLOW}${naive.trust}${RESET}, verified=${naive.checks.every((c) => c.ok)}`);
    console.log(`  ${YELLOW}every signature checks out — the forgery is internally consistent${RESET}`);

    const strict = await resolveHead({ rpcs: [node.url], checkpoint, requireAnchor: true });
    const rejected = strict.checks.some((c) => !c.ok);
    console.log(`pinned checkpoint    → trust ${strict.trust}, verified=${!rejected}`);
    for (const failed of strict.checks.filter((c) => !c.ok)) console.log(`  ${RED}✗${RESET} ${failed.name} — ${failed.detail}`);

    assert.equal(naive.trust, "rpc-asserted", "an unanchored head must never claim stronger trust");
    assert.equal(naive.checks.every((c) => c.ok), true, "the forgery is self-consistent by construction");
    assert.equal(rejected, true, "a pinned checkpoint must reject the forgery");

    console.log(`\n${GREEN}demo passed${RESET}: consistent forgery is only caught when the head is anchored`);
  } finally {
    node.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
