// Offline verification tests: every vector is a real mainnet proof captured by
// `scripts/capture-fixtures.ts`. No network access, so `npm test` is fast and deterministic.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { b58decode, b58encode } from "../src/base58.js";
import { equalBytes, sha256 } from "../src/borsh.js";
import {
  checkpointMismatch,
  parseCheckpoint,
  validatorsHash,
  type Checkpoint,
} from "../src/checkpoint.js";
import { borshValidatorStakes, lightClientBlockHash, verifyLightClientBlock } from "../src/light-client.js";
import { computeRootFromPath } from "../src/merkle.js";
import { outcomeToHashes, verifyBlockInclusion, verifyOutcomeRoot } from "../src/outcome.js";
import { contractDataKey, valueMatchesRef, verifyStateProof } from "../src/trie.js";
import { chunkHeadersRoot, encodeInnerRest } from "../src/block-header.js";
import { bytesToHex as toHex } from "../src/bytes.js";
import type { LightClientBlockView, LightClientProof, ValidatorStake } from "../src/types.js";

const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8")) as T;

const checkpoint = fixture<Checkpoint>("checkpoint");
const view = fixture<LightClientBlockView>("light-client-block");
const signingSet = fixture<ValidatorStake[]>("signing-set");
const headHeader = fixture<{ height: number; hash: string; block_merkle_root: string; outcome_root: string }>(
  "head-header",
);

// ---------------------------------------------------------------- light client head

test("block hash is recomputed from inner_lite and matches the chain", () => {
  const computed = b58encode(lightClientBlockHash(view));
  assert.equal(computed, checkpoint.blockHash);
  assert.equal(computed, headHeader.hash);
});

test("the pinned set is the one that signs this epoch, and the view carries the next epoch's set", () => {
  assert.equal(validatorsHash(checkpoint.validators), checkpoint.validatorsHash);
  assert.equal(checkpoint.version, 2);
  // The pin is what the previous epoch committed to for this epoch; the view's own next_bps is the
  // *following* epoch's set, committed by this header's next_bp_hash.
  assert.equal(validatorsHash(view.next_bps ?? []), view.inner_lite.next_bp_hash);
  assert.notDeepEqual(
    checkpoint.validators.map((v) => v.public_key),
    (view.next_bps ?? []).map((v) => v.public_key),
    "the signing set and the next epoch's set are different sets — conflating them drops signatures",
  );
});

test("approvals are valid ed25519 signatures, attributed to the key that produced them", () => {
  const head = verifyLightClientBlock(view, { validators: checkpoint.validators });
  assert.ok(head.checks.every((c) => c.ok), JSON.stringify(head.checks.filter((c) => !c.ok)));
  assert.ok(head.approvedStakePercent > 66.67, `approved ${head.approvedStakePercent}%`);
  assert.ok(head.signatureCount >= 67);

  // Regression: verifying against the *next* epoch's set silently loses the validators whose position
  // moved at the epoch boundary, which under-counts stake and flips valid heads to REJECTED.
  const wrongSet = verifyLightClientBlock(view, { validators: view.next_bps ?? [] });
  assert.ok(
    wrongSet.approvedStakePercent < head.approvedStakePercent,
    `next_bps must not count as much stake (${wrongSet.approvedStakePercent}% vs ${head.approvedStakePercent}%)`,
  );
});

test("the signer set fixture reproduces the checkpoint exactly", () => {
  assert.equal(validatorsHash(signingSet), checkpoint.validatorsHash);
  assert.equal(signingSet.length, checkpoint.validators.length);
});

test("a head with no approvals is rejected", () => {
  const stripped: LightClientBlockView = { ...view, approvals_after_next: view.approvals_after_next.map(() => null) };
  const head = verifyLightClientBlock(stripped, { validators: checkpoint.validators });
  assert.equal(head.checks.some((c) => !c.ok), true);
  assert.equal(head.approvedStakePercent, 0);
});

test("changing any header field invalidates every approval", () => {
  const tampered: LightClientBlockView = {
    ...view,
    inner_lite: { ...view.inner_lite, outcome_root: b58encode(sha256(new TextEncoder().encode("nope"))) },
  };
  const head = verifyLightClientBlock(tampered, { validators: checkpoint.validators });
  assert.ok(head.approvedStakePercent < 66.67);
  assert.equal(head.checks.find((c) => c.name.includes(">2/3"))?.ok, false);
});

test("a checkpoint for another epoch is reported as stale, not silently accepted", () => {
  const stale = { ...checkpoint, epochId: checkpoint.nextEpochId ?? "nope" };
  const mismatch = checkpointMismatch(stale, view);
  assert.ok(mismatch?.includes("stale checkpoint"));
});

test("a corrupt checkpoint is refused at parse time", () => {
  const corrupt = { ...checkpoint, validatorsHash: b58encode(new Uint8Array(32)) };
  assert.throws(() => parseCheckpoint(corrupt), /checkpoint is corrupt/);
});

// ---------------------------------------------------------------- outcome proofs

function checkProof(proof: LightClientProof, label: string) {
  const blockHash = lightClientBlockHash(proof.block_header_lite);
  const outcome = verifyOutcomeRoot(proof, b58decode(proof.block_header_lite.inner_lite.outcome_root));
  assert.ok(outcome.verified, `${label}: ${JSON.stringify(outcome.checks)}`);
  const inclusion = verifyBlockInclusion(
    proof,
    blockHash,
    b58decode(headHeader.block_merkle_root),
    b58decode(headHeader.hash),
  );
  assert.ok(inclusion.ok, `${label}: block not included in head`);
}

for (const name of ["tx-proof-success", "tx-proof-failure"]) {
  test(`${name}: transaction outcome â†’ outcome_root â†’ head`, () => {
    const item = fixture<{ txHash: string; proof: LightClientProof }>(name);
    assert.equal(item.proof.outcome_proof.id, item.txHash);
    checkProof(item.proof, name);
  });
}

test("receipt-proof: five log hashes fold into the outcome root", () => {
  const item = fixture<{ receiptId: string; proof: LightClientProof }>("receipt-proof");
  const outcome = item.proof.outcome_proof.outcome;
  assert.ok((outcome.logs?.length ?? 0) >= 2, "fixture should carry logs");
  const hashes = outcomeToHashes(item.proof.outcome_proof.id, outcome);
  assert.equal(hashes.length, 2 + (outcome.logs?.length ?? 0));
  checkProof(item.proof, "receipt-proof");
});

test("receipt-proof-failure: a failed outcome hashes to a single status byte", () => {
  // Captured on 2026-10-25, so it cannot be checked against today's head — the property under test
  // is local to the proof (a Failure carries no payload and no logs), and that does not age.
  const item = fixture<{ receiptId: string; proof: LightClientProof }>("receipt-proof-failure");
  const outcome = item.proof.outcome_proof.outcome;
  assert.ok(outcome.status.Failure !== undefined, "fixture should be a failed outcome");
  const hashes = outcomeToHashes(item.proof.outcome_proof.id, outcome);
  assert.equal(hashes.length, 2, "no logs, no payload: id + partial outcome hash");
  const rooted = verifyOutcomeRoot(item.proof, b58decode(item.proof.block_header_lite.inner_lite.outcome_root));
  assert.ok(rooted.verified, JSON.stringify(rooted.checks));
});

test("a rewritten outcome no longer matches the outcome root", () => {
  const item = fixture<{ proof: LightClientProof }>("tx-proof-success");
  const tampered: LightClientProof = {
    ...item.proof,
    outcome_proof: {
      ...item.proof.outcome_proof,
      outcome: { ...item.proof.outcome_proof.outcome, executor_id: "attacker.near" },
    },
  };
  const outcome = verifyOutcomeRoot(tampered, b58decode(tampered.block_header_lite.inner_lite.outcome_root));
  assert.equal(outcome.verified, false);
});

test("a forged merkle path is rejected", () => {
  const item = fixture<{ proof: LightClientProof }>("tx-proof-success");
  const tampered: LightClientProof = {
    ...item.proof,
    outcome_root_proof: item.proof.outcome_root_proof.map((step, i) =>
      i === 0 ? { ...step, direction: step.direction === "Left" ? "Right" : "Left" } : step,
    ),
  };
  const outcome = verifyOutcomeRoot(tampered, b58decode(tampered.block_header_lite.inner_lite.outcome_root));
  assert.equal(outcome.verified, false);
});

// ---------------------------------------------------------------- primitives

test("contract storage: trie proof binds value to state root", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/state-proof.json", import.meta.url), "utf8"),
  ) as {
    account: string;
    key: string;
    values: { key: string; value: string }[];
    proof: string[];
    chunksAtH1: { shard: number; prev_state_root: string }[];
    blockHeight: number;
  };

  const key = Uint8Array.from(Buffer.from(fixture.key, "base64"));
  const proof = fixture.proof.map((p) => Uint8Array.from(Buffer.from(p, "base64")));
  const trieKey = contractDataKey(fixture.account, key);
  const result = verifyStateProof(proof, trieKey);

  assert.equal(result.found, true, "the key exists in the captured proof");
  const rootHex = toHex(result.root);
  const shard = fixture.chunksAtH1.find((c) => toHex(b58decode(c.prev_state_root)) === rootHex);
  assert.ok(shard, "proof folds to a state root committed in a shard's chunk header");

  const value = Uint8Array.from(Buffer.from(fixture.values[0].value, "base64"));
  assert.ok(
    valueMatchesRef(value, { length: result.valueLength!, hash: result.valueHash! }),
    "returned value hashes to the leaf commitment",
  );
});

test("contract storage: a rewritten value no longer matches the leaf", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/state-proof.json", import.meta.url), "utf8"),
  ) as { values: { value: string }[]; proof: string[]; account: string; key: string };
  const proof = fixture.proof.map((p) => Uint8Array.from(Buffer.from(p, "base64")));
  const key = Uint8Array.from(Buffer.from(fixture.key, "base64"));
  const result = verifyStateProof(proof, contractDataKey(fixture.account, key));
  const lie = Uint8Array.from(Buffer.from(fixture.values[0].value, "base64"));
  lie[lie.length - 1] ^= 0xff;
  assert.equal(valueMatchesRef(lie, { length: result.valueLength!, hash: result.valueHash! }), false);
});

test("contract storage: an absent key is reported as absent, not as a value", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/state-proof.json", import.meta.url), "utf8"),
  ) as { account: string; proof: string[] };
  const proof = fixture.proof.map((p) => Uint8Array.from(Buffer.from(p, "base64")));
  const other = contractDataKey(fixture.account, new TextEncoder().encode("NOT_A_REAL_KEY"));
  const result = verifyStateProof(proof, other);
  assert.equal(result.found, false);
});

test("contract storage: dropping a proof node breaks the walk", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/state-proof.json", import.meta.url), "utf8"),
  ) as { account: string; key: string; proof: string[] };
  const proof = fixture.proof.map((p) => Uint8Array.from(Buffer.from(p, "base64")));
  const key = Uint8Array.from(Buffer.from(fixture.key, "base64"));
  const shortened = proof.slice(0, proof.length - 1);
  assert.throws(() => verifyStateProof(shortened, contractDataKey(fixture.account, key)), /missing/);
});

test("block header: inner_rest and chunk_headers_root are reproducible offline", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/block-anchor.json", import.meta.url), "utf8"),
  ) as {
    inner_rest_hash: string;
    chunk_headers_root: string;
    header: any;
    chunks: any[];
  };

  const innerRestHash = sha256(encodeInnerRest(fixture.header));
  assert.ok(
    equalBytes(innerRestHash, b58decode(fixture.inner_rest_hash)),
    "sha256(borsh(inner_rest)) must equal the head's inner_rest_hash",
  );

  const root = chunkHeadersRoot(fixture.chunks);
  assert.ok(
    equalBytes(root, b58decode(fixture.chunk_headers_root)),
    "merklize(ChunkHashHeight) must equal chunk_headers_root",
  );
});

test("block header: a tampered state root breaks the chunk root", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./fixtures/block-anchor.json", import.meta.url), "utf8"),
  ) as { chunk_headers_root: string; chunks: any[] };

  const tampered = fixture.chunks.map((chunk, index) =>
    index === 0 ? { ...chunk, prev_state_root: b58encode(new Uint8Array(32).fill(7)) } : chunk,
  );
  assert.equal(
    equalBytes(chunkHeadersRoot(tampered), b58decode(fixture.chunk_headers_root)),
    false,
  );
});

test("validator set borsh is stable", () => {
  // Guards against an accidental serialization change: the hash must equal the header commitment.
  const hash = sha256(borshValidatorStakes(view.next_bps ?? []));
  assert.ok(equalBytes(hash, b58decode(view.inner_lite.next_bp_hash)));
});

test("merkle root of an empty path is the leaf itself", () => {
  const leaf = sha256(new TextEncoder().encode("leaf"));
  assert.ok(equalBytes(computeRootFromPath([], leaf), leaf));
});

