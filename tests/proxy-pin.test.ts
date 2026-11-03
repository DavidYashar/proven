// A pin the proxy walked forward must be *kept*: adopted once, reported by /status, and not re-walked
// on the next refresh. Offline: the whole chain is synthetic and served from localhost.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";

import { b58encode } from "../src/base58.js";
import { sha256 } from "../src/borsh.js";
import { validatorsHash, type Checkpoint } from "../src/checkpoint.js";
import { approvalMessage, borshValidatorStakes, lightClientBlockHash, nextBlockHash } from "../src/light-client.js";
import { createProvenProxy } from "../src/proxy.js";
import type { LightClientBlockView, ValidatorStake } from "../src/types.js";

const random32 = (): Uint8Array => ed25519.utils.randomSecretKey();
const epochId = (): string => b58encode(random32());

function validatorSet(count = 4): { stakes: ValidatorStake[]; secrets: Uint8Array[] } {
  const secrets = Array.from({ length: count }, () => random32());
  const stakes = secrets.map((secret, i) => ({
    account_id: `v${i}.near`,
    public_key: `ed25519:${b58encode(ed25519.getPublicKey(secret))}`,
    stake: "1000000000000000000000000",
  }));
  return { stakes, secrets };
}

/** A light client block for `epoch` signed by `signers`, committing to `nextBps` as the next set. */
function viewFor(options: {
  height: number;
  epoch: string;
  nextEpoch: string;
  signers: Uint8Array[];
  nextBps: ValidatorStake[];
  prev: string;
}): LightClientBlockView {
  const view = {
    prev_block_hash: options.prev,
    next_block_inner_hash: b58encode(random32()),
    inner_lite: {
      height: options.height,
      epoch_id: options.epoch,
      next_epoch_id: options.nextEpoch,
      prev_state_root: b58encode(random32()),
      outcome_root: b58encode(random32()),
      timestamp: Date.now() * 1_000_000,
      next_bp_hash: b58encode(sha256(borshValidatorStakes(options.nextBps))),
      block_merkle_root: b58encode(random32()),
    },
    inner_rest_hash: b58encode(random32()),
    next_bps: options.nextBps,
    approvals_after_next: [] as (string | null)[],
  } as LightClientBlockView;
  const message = approvalMessage(nextBlockHash(view, lightClientBlockHash(view)), options.height);
  view.approvals_after_next = options.signers.map((secret) => `ed25519:${b58encode(ed25519.sign(message, secret))}`);
  return view;
}

test("the proxy keeps a walked pin instead of re-walking it on every refresh", async (t) => {
  const e1 = epochId();
  const e2 = epochId();
  const e3 = epochId();
  const s1 = validatorSet();
  const s2 = validatorSet();
  const s3 = validatorSet();

  const view1 = viewFor({
    height: 100,
    epoch: e1,
    nextEpoch: e2,
    signers: s1.secrets,
    nextBps: s2.stakes,
    prev: b58encode(random32()),
  });
  const view2 = viewFor({
    height: 200,
    epoch: e2,
    nextEpoch: e3,
    signers: s2.secrets,
    nextBps: s3.stakes,
    prev: b58encode(random32()),
  });
  const headHash = b58encode(lightClientBlockHash(view2));

  // A pin for the *previous* epoch, exactly as `proven checkpoint` would have written it.
  const pin: Checkpoint = {
    version: 3,
    network: "mainnet",
    epochId: e1,
    nextEpochId: e2,
    height: view1.inner_lite.height,
    blockHash: b58encode(lightClientBlockHash(view1)),
    validators: s1.stakes,
    validatorsHash: validatorsHash(s1.stakes),
    nextValidators: s2.stakes,
  };

  let walks = 0;
  const upstream = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk: Buffer) => {
      raw += chunk.toString();
    });
    req.on("end", () => {
      const request = JSON.parse(raw) as { id: unknown; method: string };
      const reply = (result: unknown) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
      };
      if (request.method === "next_light_client_block") {
        walks++;
        reply(view2);
      } else if (request.method === "block") {
        // Both the final-head probe and the canonical-block check land on the head we serve.
        reply({ header: { height: view2.inner_lite.height, hash: headHash, epoch_id: e2, next_epoch_id: e3 } });
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: request.method } }));
      }
    });
  });
  await new Promise<void>((resolve) => {
    upstream.listen(0, "127.0.0.1", () => resolve());
  });
  t.after(() => upstream.close());

  const adopted: Checkpoint[] = [];
  const proxy = createProvenProxy({
    upstream: [`http://127.0.0.1:${(upstream.address() as any).port}`],
    checkpoint: pin,
    onRolled: (next) => adopted.push(next),
  });
  const server = await proxy.listen(0, "127.0.0.1");
  t.after(() => server.close());
  const port = (server.address() as any).port;
  const status = async (): Promise<any> => (await fetch(`http://127.0.0.1:${port}/status`)).json();

  const first = await status();
  assert.equal(first.head.trust, "anchored", "the walked pin must authenticate the head");
  assert.equal(first.checkpoint.epochId, e2, "/status must report the epoch the walk reached");
  assert.equal(first.checkpoint.rolled, true);
  assert.equal(adopted.length, 1, "a walked pin is adopted exactly once");
  // One call fetches the head, a second performs the hop — that is the cost we want to pay only once.
  assert.equal(walks, 2, `first refresh should fetch the head and walk one hop (was ${walks})`);
  const afterFirst = walks;

  // The adopted pin must be complete, not just relabelled: every field describes the new epoch.
  const kept = adopted[0];
  assert.equal(kept.epochId, e2);
  assert.equal(kept.nextEpochId, e3);
  assert.equal(kept.height, view2.inner_lite.height);
  assert.equal(kept.blockHash, headHash);
  assert.equal(kept.validatorsHash, validatorsHash(s2.stakes), "the signers must be the set that signs this epoch");
  assert.equal(kept.nextValidators?.length, s3.stakes.length, "the following epoch's set must be carried forward");

  // Past the head cache, a second refresh must reuse the pin rather than walk the chain again.
  await new Promise((r) => setTimeout(r, 5_500));
  const second = await status();
  assert.equal(second.checkpoint.epochId, e2);
  assert.equal(adopted.length, 1, "the pin is adopted once, not on every refresh");
  assert.equal(walks - afterFirst, 1, `second refresh should fetch the head only, with no hop (added ${walks - afterFirst})`);
});
