#!/usr/bin/env node
// A stand-in for "my app": it knows nothing about proofs, only a NEAR RPC URL.
//
//   NEAR_RPC_URL=http://localhost:8080 node examples/simple-app.mjs
//
// The only thing it does differently from any other NEAR app is read the `x-proven-*` headers and
// refuse to act on an answer that was not verified. That is the whole integration.
const RPC = process.env.NEAR_RPC_URL ?? "http://localhost:8080";

/** Every call returns the payload plus the proxy's verdict on it. */
async function rpc(method, params) {
  const response = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const verdict = {
    verified: response.headers.get("x-proven-verified") ?? "none",
    trust: response.headers.get("x-proven-trust") ?? "none",
    scope: response.headers.get("x-proven-scope") ?? "",
    detail: decodeURIComponent(response.headers.get("x-proven-detail") ?? ""),
  };
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return { result: body.result, verdict };
}

/**
 * The one habit this tool is for: only act on `true`. `unverified` means "nobody proved this" — it is
 * not a pass, and it is not an accusation either.
 */
function mustBeVerified({ verdict }, what) {
  const ok = verdict.verified === "true" && verdict.trust === "anchored";
  console.log(`  ${(ok ? "ACT" : "STOP").padEnd(4)} ${what.padEnd(24)} verified=${verdict.verified.padEnd(10)} trust=${verdict.trust}`);
  if (!ok) console.log(`       ↳ would not act: ${verdict.detail} ${verdict.scope}`);
  return ok;
}

const step = (title) => console.log(`\n=== ${title} ===`);

// ---------------------------------------------------------------- 1. talk to it
step("1. the endpoint answers at all");
const { result: status, verdict: statusVerdict } = await rpc("status", {});
console.log(`  chain: ${status.chain_id}  latest block: ${status.sync_info?.latest_block_height}`);
console.log(
  `  verified=${statusVerdict.verified} (status has no proof primitive, so the proxy says so instead of pretending)`,
);

// ---------------------------------------------------------------- 2. a recent transaction
step("2. a real transaction, with its verdict");
let sample = null;
for (let back = 6; back < 40 && !sample; back++) {
  const { result: final } = await rpc("block", { finality: "final" });
  const at = Number(final.header.height) - back;
  const block = await rpc("block", { block_id: at }).catch(() => null);
  for (const chunkInfo of block?.result?.chunks ?? []) {
    const chunk = await rpc("chunk", { block_id: block.result.header.hash, shard_id: chunkInfo.shard_id }).catch(
      () => null,
    );
    const tx = (chunk?.result?.transactions ?? [])[0];
    if (tx) {
      sample = { hash: tx.hash, signer: tx.signer_id };
      break;
    }
  }
}
if (!sample) {
  console.log("  could not find a recent transaction (the endpoint may be rate-limiting; try again)");
} else {
  const { result: tx, verdict } = await rpc("EXPERIMENTAL_tx_status", {
    tx_hash: sample.hash,
    sender_account_id: sample.signer,
  });
  console.log(`  ${sample.hash.slice(0, 12)}… (${sample.signer})`);
  console.log(`  outcome: ${JSON.stringify(tx.status).slice(0, 70)}`);
  console.log(`  scope:   ${verdict.scope}`);
  mustBeVerified({ verdict }, "credit the deposit");
}

// ---------------------------------------------------------------- 3. contract storage
step("3. a contract's stored value, with its proof");
const { result: state, verdict: stateVerdict } = await rpc("query", {
  request_type: "view_state",
  account_id: "mpc-prover-0_4_12.bridge.near",
  prefix_base64: Buffer.from("STATE").toString("base64"),
  include_proof: true,
  finality: "final",
});
console.log(`  keys returned: ${state.values.length}, first 40 bytes: ${state.values[0]?.value.slice(0, 40)}…`);
mustBeVerified({ verdict: stateVerdict }, "read the storage");

// ---------------------------------------------------------------- 4. the point
step("4. what the headers mean");
console.log("  true        the proof checked out against signed validators");
console.log("  self        the header hash was recomputed; nothing else was proven");
console.log("  unverified  nobody proved this (no proof exists, or the transaction is still running)");
console.log("  false       the answer contradicts the chain — the proxy refuses to hand it back");
console.log("\n  trust anchored = a pinned validator set signed it (>2/3 of real stake)");
console.log("  Ready. Point NEAR_RPC_URL at any endpoint: a lying one cannot reach 'true'.");
