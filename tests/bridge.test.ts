// The epoch walk: a pin is advanced one epoch at a time, each step signed by the set the previous
// step committed to. Synthetic blocks, so it runs offline and deterministically.
import assert from "node:assert/strict";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";

import { b58encode } from "../src/base58.js";
import { sha256 } from "../src/borsh.js";
import { bridgeCheckpoint, makeCheckpoint, validatorsHash, type Checkpoint } from "../src/checkpoint.js";
import { approvalMessage, borshValidatorStakes, lightClientBlockHash, nextBlockHash } from "../src/light-client.js";
import { NearRpc } from "../src/rpc.js";
import { resolveHead } from "../src/trust.js";
import type { LightClientBlockView, ValidatorStake } from "../src/types.js";

const random32 = (): Uint8Array => ed25519.utils.randomSecretKey();
/** Epoch ids are 32-byte hashes, so they must be base58. */
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

/**
 * A light client block for `epochId` whose approvals are signed by `signers`, and which commits to
 * `nextBps` as the following epoch's producers.
 */
function viewFor(options: {
  height: number;
  epochId: string;
  nextEpochId: string;
  signers: Uint8Array[];
  nextBps: ValidatorStake[];
  prev: string;
}): LightClientBlockView {
  const view = {
    prev_block_hash: options.prev,
    next_block_inner_hash: b58encode(random32()),
    inner_lite: {
      height: options.height,
      epoch_id: options.epochId,
      next_epoch_id: options.nextEpochId,
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

/** An RPC that answers "the light client block after this hash" from a fixed map. */
function chainRpc(pairs: Array<[string, LightClientBlockView]>): NearRpc {
  const byHash = new Map(pairs);
  return {
    async nextLightClientBlock(lastBlockHash: string) {
      return byHash.get(lastBlockHash) ?? null;
    },
  } as unknown as NearRpc;
}

test("a stale pin walks forward one epoch at a time", async () => {
  const v0 = validatorSet();
  const v1 = validatorSet();
  const v2 = validatorSet();
  const v3 = validatorSet();
  const prev = b58encode(random32());
  const e0 = epochId();
  const e1 = epochId();
  const e2 = epochId();
  const e3 = epochId();

  // epoch0 is signed by v0 and commits to v1; epoch1 is signed by v1 and commits to v2.
  const epoch0 = viewFor({ height: 100, epochId: e0, nextEpochId: e1, signers: v0.secrets, nextBps: v1.stakes, prev });
  const epoch1 = viewFor({
    height: 200,
    epochId: e1,
    nextEpochId: e2,
    signers: v1.secrets,
    nextBps: v2.stakes,
    prev: b58encode(lightClientBlockHash(epoch0)),
  });
  const epoch2 = viewFor({
    height: 300,
    epochId: e2,
    nextEpochId: e3,
    signers: v2.secrets,
    nextBps: v3.stakes,
    prev: b58encode(lightClientBlockHash(epoch1)),
  });

  const pin: Checkpoint = {
    version: 3,
    network: "mainnet",
    epochId: e0,
    nextEpochId: e1,
    height: 100,
    blockHash: b58encode(lightClientBlockHash(epoch0)),
    validators: v0.stakes,
    validatorsHash: validatorsHash(v0.stakes),
    nextValidators: v1.stakes,
  };

  const bridged = await bridgeCheckpoint(
    chainRpc([[pin.blockHash, epoch1], [b58encode(lightClientBlockHash(epoch1)), epoch2]]),
    pin,
    e2,
  );
  assert.ok(bridged, "the walk should succeed");
  assert.equal(bridged.steps, 2);
  assert.equal(bridged.checkpoint.epochId, e2);
  assert.equal(bridged.checkpoint.nextEpochId, e3);
  assert.equal(bridged.checkpoint.height, epoch2.inner_lite.height);
  assert.equal(bridged.checkpoint.blockHash, b58encode(lightClientBlockHash(epoch2)));
  assert.equal(bridged.checkpoint.validatorsHash, validatorsHash(v2.stakes));
  assert.deepEqual(bridged.checkpoint.validators, v2.stakes);
  assert.deepEqual(bridged.checkpoint.nextValidators, v3.stakes);
});

test("the walk refuses a block signed by the wrong epoch's set", async () => {
  const v0 = validatorSet();
  const v1 = validatorSet();
  const impostor = validatorSet();
  const e0 = epochId();
  const e1 = epochId();

  const epoch1 = viewFor({
    height: 200,
    epochId: e1,
    nextEpochId: epochId(),
    signers: impostor.secrets, // not the set the pin committed to
    nextBps: v1.stakes,
    prev: b58encode(random32()),
  });

  const pin: Checkpoint = {
    version: 3,
    network: "mainnet",
    epochId: e0,
    nextEpochId: e1,
    height: 100,
    blockHash: b58encode(random32()),
    validators: v0.stakes,
    validatorsHash: validatorsHash(v0.stakes),
    nextValidators: v1.stakes,
  };

  assert.equal(await bridgeCheckpoint(chainRpc([[pin.blockHash, epoch1]]), pin, e1), null);
});

test("the walk refuses to skip an epoch", async () => {
  const v0 = validatorSet();
  const v1 = validatorSet();
  const v2 = validatorSet();
  const e0 = epochId();
  const e1 = epochId();
  const e3 = epochId();

  // A view for an epoch the held set does not cover: one hop must advance exactly one epoch.
  const farAhead = viewFor({
    height: 300,
    epochId: e3,
    nextEpochId: epochId(),
    signers: v2.secrets,
    nextBps: v0.stakes,
    prev: b58encode(random32()),
  });

  const pin: Checkpoint = {
    version: 3,
    network: "mainnet",
    epochId: e0,
    nextEpochId: e1,
    height: 100,
    blockHash: b58encode(random32()),
    validators: v0.stakes,
    validatorsHash: validatorsHash(v0.stakes),
    nextValidators: v1.stakes,
  };

  assert.equal(await bridgeCheckpoint(chainRpc([[pin.blockHash, farAhead]]), pin, e3), null);
});

test("a v2 pin has nothing to walk with", async () => {
  const v0 = validatorSet();
  const pin: Checkpoint = {
    version: 2,
    network: "mainnet",
    epochId: epochId(),
    nextEpochId: epochId(),
    height: 100,
    blockHash: b58encode(random32()),
    validators: v0.stakes,
    validatorsHash: validatorsHash(v0.stakes),
  };
  assert.equal(await bridgeCheckpoint(chainRpc([]), pin, epochId()), null);
});

test("failed bridges wait five minutes, but changing providers can recover immediately", async (t) => {
  const v0 = validatorSet();
  const v1 = validatorSet();
  const e0 = epochId();
  const e1 = epochId();
  const epoch0 = viewFor({
    height: 100, epochId: e0, nextEpochId: e1,
    signers: v0.secrets, nextBps: v1.stakes, prev: b58encode(random32()),
  });
  const pin = makeCheckpoint(epoch0, v0.stakes);
  const current = viewFor({
    height: 200, epochId: e1, nextEpochId: epochId(),
    signers: v1.secrets, nextBps: v1.stakes, prev: pin.blockHash,
  });
  let prunedWalks = 0;
  let archivalWalks = 0;
  const provider = (archival: boolean) => new NearRpc({
    url: archival ? "http://archival.test" : "http://pruned.test",
    fetchImpl: async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as {
        method: string; params: { last_block_hash?: string };
      };
      let result: unknown;
      if (request.method === "block") {
        result = { header: { height: current.inner_lite.height + 3, hash: b58encode(lightClientBlockHash(current)) } };
      } else {
        assert.equal(request.method, "next_light_client_block");
        const walking = request.params.last_block_hash === pin.blockHash;
        if (walking) {
          if (archival) archivalWalks++;
          else prunedWalks++;
        }
        result = walking && !archival ? null : current;
      }
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: "test", result }));
    },
  });
  const pruned = provider(false);
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });

  const first = await resolveHead({ rpcs: [pruned], checkpoint: pin });
  assert.equal(prunedWalks, 1);
  assert.match(first.notes.join(";"), /will retry in 5 minutes/);
  t.mock.timers.tick(5 * 60_000 - 1);
  const cooled = await resolveHead({ rpcs: [pruned], checkpoint: pin });
  assert.equal(prunedWalks, 1, "no bridge request before the retry deadline");
  assert.match(cooled.notes.join(";"), /failed less than 5 minutes ago/);

  const recovered = await resolveHead({ rpcs: [provider(true)], checkpoint: pin, requireAnchor: true });
  assert.equal(archivalWalks, 1, "a different provider must not inherit the cooldown");
  assert.equal(recovered.trust, "anchored");
  assert.ok(recovered.checks.every((check) => check.ok));
  assert.equal(recovered.bridgedPin?.epochId, e1);

  t.mock.timers.tick(1);
  await resolveHead({ rpcs: [pruned], checkpoint: pin });
  assert.equal(prunedWalks, 2, "retry at exactly five minutes");
});
