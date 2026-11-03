// Regression tests for two holes that let a hostile RPC get a fabricated contract value back as
// VERIFIED. Both are offline: the head comes from the recorded fixtures, and only the `query` and
// `block` answers are stubbed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { b58encode } from "../src/base58.js";
import { u32, u64, concat, sha256 } from "../src/borsh.js";
import { validatorsHash, type Checkpoint } from "../src/checkpoint.js";
import { verifyLightClientBlock } from "../src/light-client.js";
import { NearRpc } from "../src/rpc.js";
import { verifyContractState } from "../src/state.js";
import { contractDataKey } from "../src/trie.js";
import type { LightClientBlockView } from "../src/types.js";

const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8")) as T;

const checkpoint = fixture<Checkpoint>("checkpoint");
const view = fixture<LightClientBlockView>("light-client-block");
const stateProof = fixture<{ account: string; key: string; values: { value: string }[]; proof: string[] }>(
  "state-proof",
);

const FAKE = new TextEncoder().encode("attacker-balance:1000000");

/** A head as `resolveHead` would have produced it from a valid pin. */
function trustedHead() {
  const head = verifyLightClientBlock(view, { validators: checkpoint.validators });
  return {
    head,
    view,
    trust: "anchored" as const,
    signers: checkpoint.validators,
    signerSource: "pinned checkpoint",
    checks: head.checks,
    notes: [],
  };
}

/** Serves the recorded proof, with the payload swapped for a value nothing commits to. */
function stubRpc(options: { block: "real-junk" | "unreadable" }): NearRpc {
  const fetchImpl = (async (_url: any, init: any) => {
    const request = JSON.parse(String(init?.body ?? "{}"));
    const reply = (body: unknown) =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: "t", ...(body as object) }), {
        headers: { "content-type": "application/json" },
      });

    if (request.method === "query") {
      return reply({
        result: {
          values: [{ key: request.params.prefix_base64, value: Buffer.from(FAKE).toString("base64") }],
          proof: stateProof.proof,
        },
      });
    }
    if (request.method === "block") {
      // A header this verifier cannot authenticate: the anchoring step must fail closed, not vanish.
      return reply({ result: { header: {}, chunks: [] } });
    }
    return reply({ error: { message: "unexpected method" } });
  }) as typeof fetch;
  return new NearRpc({ url: "http://stub.invalid", fetchImpl });
}

test("a value the trie does not commit to is never reported as verified", async () => {
  const result = await verifyContractState(stateProof.account, new TextEncoder().encode("STATE"), {
    rpc: stubRpc({ block: "real-junk" }),
    checkpoint,
    resolvedHead: trustedHead(),
  });

  assert.equal(result.verified, false, "a forged value must not verify");
  assert.equal(result.value.value, null, "the uncommitted value must not be surfaced");
  assert.equal(result.value.valueText, null);
});

test("an unauthenticated header is a failed check, not a note", async () => {
  const result = await verifyContractState(stateProof.account, new TextEncoder().encode("STATE"), {
    rpc: stubRpc({ block: "unreadable" }),
    checkpoint,
    resolvedHead: trustedHead(),
  });

  const anchoring = result.checks.find((c) => c.name === "state root is committed by the head's chunk headers");
  assert.ok(anchoring, "the anchoring step must always report a check");
  assert.equal(anchoring!.ok, false);
  assert.equal(result.verified, false);
});

test("a fabricated single-node path never anchors, and its value is not surfaced", async () => {
  // A leaf the attacker wrote themselves: consistent on its own, but its root is in no chunk header.
  const absentKey = new TextEncoder().encode("NOT_A_REAL_KEY");
  const trieKey = contractDataKey(stateProof.account, absentKey);
  const leaf = concat(
    Uint8Array.of(0),
    u32(trieKey.length + 1),
    Uint8Array.of(0x20),
    trieKey,
    u32(FAKE.length),
    sha256(FAKE),
    u64(0),
  );
  const fetchImpl = (async (_url: any, init: any) => {
    const request = JSON.parse(String(init?.body ?? "{}"));
    const reply = (body: unknown) =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: "t", ...(body as object) }), {
        headers: { "content-type": "application/json" },
      });
    if (request.method === "query") {
      return reply({
        result: {
          values: [{ key: request.params.prefix_base64, value: Buffer.from(FAKE).toString("base64") }],
          proof: [Buffer.from(leaf).toString("base64")],
        },
      });
    }
    if (request.method === "block") return reply({ result: { header: {}, chunks: [] } });
    return reply({ error: { message: "unexpected method" } });
  }) as typeof fetch;

  const result = await verifyContractState(stateProof.account, absentKey, {
    rpc: new NearRpc({ url: "http://stub.invalid", fetchImpl }),
    checkpoint,
    resolvedHead: trustedHead(),
  });

  assert.equal(result.verified, false);
  assert.equal(result.value.value, null, "the fabricated value must not be surfaced");
});

test("the fixture checkpoint is internally consistent", () => {
  assert.equal(validatorsHash(checkpoint.validators), checkpoint.validatorsHash);
  assert.ok(checkpoint.validators.length > 0);
});
