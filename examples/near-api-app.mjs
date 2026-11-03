#!/usr/bin/env node
// "My existing NEAR app", unchanged except for the RPC URL.
//
//   NEAR_RPC_URL=http://localhost:8080 node examples/near-api-app.mjs
//
// This uses near-api-js exactly as any dapp does — no imports from this project, no proof code. The
// only addition is a `fetch` wrapper that records the `x-proven-*` headers the proxy attaches, so the
// app can see the difference between a value that was proven and a value that was merely forwarded.
import { JsonRpcProvider } from "near-api-js";

const RPC = process.env.NEAR_RPC_URL ?? "http://localhost:8080";
const ACCOUNT = process.env.NEAR_ACCOUNT ?? "wrap.near";
const PROVABLE = process.env.NEAR_PROVABLE_CONTRACT ?? "mpc-prover-0_4_12.bridge.near";

// near-api-js does not expose response headers, so record what the proxy said about each request.
const verdicts = [];
const realFetch = fetch;
globalThis.fetch = async (input, init) => {
  const response = await realFetch(input, init);
  let method = "";
  try {
    method = JSON.parse(String(init?.body ?? "{}")).method ?? "";
  } catch {}
  verdicts.push({
    method,
    verified: response.headers.get("x-proven-verified") ?? "none",
    trust: response.headers.get("x-proven-trust") ?? "none",
    detail: decodeURIComponent(response.headers.get("x-proven-detail") ?? ""),
  });
  return response;
};

const provider = new JsonRpcProvider({ url: RPC });
const blockQuery = { finality: "final" };
const last = () => verdicts[verdicts.length - 1];
const line = (v) => `verified=${v.verified.padEnd(10)} trust=${v.trust}`;

/** What the app is told about this call, and why — never just "ok". */
const honest = (v) => (v.verified === "true" ? `✓ ${line(v)}` : `· ${line(v)}  (${v.detail || "no proof primitive"})`);

console.log(`\n=== near-api-js -> ${RPC} ===`);
console.log(`account ${ACCOUNT}\n`);

// 1. the head — a `block` call. The proxy recomputes the header hash, so it is labelled `self`.
const block = await provider.viewBlock(blockQuery);
console.log(`head              ${block.header.height}  (epoch ${block.header.epoch_id.slice(0, 8)}…)`);
console.log(`                  ${honest(last())}`);

// 2. an account balance — a plain `query`, which carries no proof at all.
const account = await provider.viewAccount({ accountId: ACCOUNT, blockQuery });
console.log(`\nbalance           ${Number(account.amount) / 1e24} NEAR`);
console.log(`                  ${honest(last())}`);

// 3. a contract call — also a plain `query`.
const supply = await provider.callFunction({ contractId: ACCOUNT, method: "ft_total_supply", args: {}, blockQuery });
console.log(`\nft_total_supply   ${supply}`);
console.log(`                  ${honest(last())}`);

// 4. the same kind of read, asked for *with* a proof: one extra parameter changes what is knowable.
//    Not every contract can serve one — a large state is refused by the node, and the proxy says so
//    instead of pretending either way.
const proveState = async (contractId) => {
  const response = await realFetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "query",
      params: {
        request_type: "view_state",
        account_id: contractId,
        prefix_base64: Buffer.from("STATE").toString("base64"),
        include_proof: true,
        finality: "final",
      },
    }),
  });
  const body = await response.json();
  return {
    contractId,
    value: body.result?.values?.[0]?.value ?? null,
    verified: response.headers.get("x-proven-verified") ?? "none",
    trust: response.headers.get("x-proven-trust") ?? "none",
    error: body.error?.cause?.name ?? null,
  };
};

console.log(`\nstorage, with a proof`);
for (const contractId of [ACCOUNT, PROVABLE]) {
  const state = await proveState(contractId);
  console.log(`  ${contractId.padEnd(30)} ${state.value ? `${state.value.slice(0, 28)}…` : "(no such key)"}`);
  console.log(
    `    verified=${state.verified.padEnd(10)} trust=${state.trust}${state.error ? `  (node refused: ${state.error})` : ""}`,
  );
}

// 5. say what the difference means, because it is the point
const proven = verdicts.filter((v) => v.verified === "true").length;
console.log(`\n--- summary ---`);
console.log(`  ${proven} of ${verdicts.length} JSON-RPC calls from near-api-js arrived with a full proof.`);
console.log(`  The rest arrived as 'unverified' or 'self': near-api-js never asks for a proof, so that`);
console.log(`  data is the endpoint's word — exactly as it is in every NEAR app today. Adding`);
console.log(`  include_proof is what turns a read into something the proxy can check, and the verdict`);
console.log(`  is what lets the app decide. A lying endpoint can never reach 'true'.`);
