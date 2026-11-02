// Captures frozen, real mainnet fixtures for offline verification tests.
//   npx tsx scripts/capture-fixtures.ts
// Fixtures are committed so `npm test` needs no network.
import { writeFileSync, mkdirSync } from "node:fs";
import { NearRpc } from "../src/rpc.js";
import { b58encode } from "../src/base58.js";
import { borshValidatorStakes, lightClientBlockHash } from "../src/light-client.js";
import { makeCheckpoint } from "../src/checkpoint.js";
import { fetchSignerSet } from "../src/trust.js";
import { sha256 } from "../src/borsh.js";

const RPC = process.env.RPC ?? "https://free.rpc.fastnear.com";
const rpc = new NearRpc(RPC);
const outDir = new URL("../tests/fixtures/", import.meta.url);
mkdirSync(outDir, { recursive: true });

const write = (name: string, value: unknown) => {
  writeFileSync(new URL(name, outDir), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`  wrote ${name}`);
};

// --- 1. light client block + the header it authenticates ---
const final = await rpc.finalBlock();
let view: any = null;
for (let back = 0; back < 6 && !view; back++) {
  const block = await rpc.block(Number(final.header.height) - back);
  const candidate = await rpc.nextLightClientBlock(block.header.hash);
  if (candidate?.inner_lite) view = candidate;
}
const headHeight = Number(view.inner_lite.height);
// The RPC sometimes answers with a light client block slightly ahead of the block it reports as
// final; wait until the chain catches up so the proof requests are accepted.
let headHeader = await rpc.block(headHeight).catch(() => null);
for (let i = 0; i < 20; i++) {
  const f = await rpc.finalBlock();
  if (Number(f.header.height) >= headHeight) {
    headHeader = await rpc.block(headHeight);
    break;
  }
  await new Promise((r) => setTimeout(r, 1500));
}
if (!headHeader) throw new Error("could not fetch the head header");
const blockHash = b58encode(lightClientBlockHash(view));

// The producers that sign `view`'s epoch are the *previous* epoch's `next_bps` — not `view.next_bps`,
// which belongs to the next epoch.
const signers = await fetchSignerSet(rpc, view.inner_lite.epoch_id, headHeight);
if (!signers) throw new Error("could not obtain the producer set that signs this epoch");
const checkpoint = {
  _comment:
    "Captured from mainnet. `validators` are the producers that sign blocks in `epochId` (the previous epoch's next_bps).",
  ...makeCheckpoint(view, signers, { network: "mainnet", sourceRpc: RPC }),
};
write("checkpoint.json", checkpoint);
write("light-client-block.json", view);
write("signing-set.json", signers);
write("head-header.json", {
  height: headHeight,
  hash: headHeader.header.hash,
  block_merkle_root: headHeader.header.block_merkle_root,
  outcome_root: headHeader.header.outcome_root,
});

// --- 2. a successful transaction proof + a failed one ---
// NearBlocks is used only to *find* candidates cheaply; all proofs come from the RPC.
async function candidates(wantFailure: boolean, limit = 100): Promise<{ hash: string; signer: string }[]> {
  const res = await fetch(`https://api.nearblocks.io/v3/txns?limit=${limit}`);
  const json: any = await res.json();
  return (json.data ?? [])
    .filter((t: any) => (wantFailure ? t.outcomes?.status === false : t.outcomes?.status === true))
    .filter((t: any) => t.signer_account_id && t.receiver_account_id !== "v1.signer")
    // the proven block must not be ahead of the light client head
    .filter((t: any) => Number(t.block?.block_height ?? 0) <= headHeight)
    .map((t: any) => ({ hash: t.transaction_hash, signer: t.signer_account_id }));
}

async function findProof(wantFailure: boolean) {
  for (const candidate of await candidates(wantFailure)) {
    try {
      const proof = await rpc.lightClientProofTransaction(candidate.hash, candidate.signer, headHeader.header.hash);
      const status = (await rpc.txStatus(candidate.hash, candidate.signer)).transaction_outcome.outcome.status;
      return { txHash: candidate.hash, signer: candidate.signer, proof, status };
    } catch {
      continue;
    }
  }
  return null;
}

const ok = await findProof(false);
if (ok) {
  write("tx-proof-success.json", {
    txHash: ok.txHash,
    signer: ok.signer,
    headHash: headHeader.header.hash,
    proof: ok.proof,
    status: ok.status,
  });
}
const bad = await findProof(true);
if (bad) {
  write("tx-proof-failure.json", {
    txHash: bad.txHash,
    signer: bad.signer,
    headHash: headHeader.header.hash,
    proof: bad.proof,
    status: bad.status,
  });
} else {
  console.log("  (no failed transaction proof captured)");
}

// --- 3 & 4. receipt proofs: one with logs, one that failed ---
// NearBlocks' `outcomes.status` covers the whole transaction *including* receipts, so most
// "failed" transactions are actually successful txs whose receipt panicked. Those receipt proofs
// are what exercises the one-byte `PartialExecutionStatus::Failure` encoding.
async function findReceiptProof(want: "logs" | "failure") {
  const pool = [...(await candidates(want === "failure", 100)), ...(await candidates(false, 100))];
  for (const candidate of pool) {
    let st: any;
    try {
      st = await rpc.txStatus(candidate.hash, candidate.signer);
    } catch {
      continue;
    }
    const receiptsById = new Map<string, any>((st.receipts ?? []).map((r: any) => [r.receipt_id, r]));
    for (const outcome of st.receipts_outcome ?? []) {
      const matched =
        want === "failure"
          ? outcome.outcome.status?.Failure !== undefined
          : (outcome.outcome.logs ?? []).length >= 2;
      if (!matched) continue;
      const receipt = receiptsById.get(outcome.id);
      if (!receipt) continue;
      try {
        const proof = await rpc.lightClientProofReceipt(receipt.receipt_id, receipt.receiver_id, headHeader.header.hash);
        return {
          receiptId: receipt.receipt_id,
          receiver: receipt.receiver_id,
          headHash: headHeader.header.hash,
          proof,
          outcomeStatus: outcome.outcome.status,
        };
      } catch {
        continue;
      }
    }
  }
  return null;
}

const withLogs = await findReceiptProof("logs");
if (withLogs) write("receipt-proof.json", withLogs);
else console.log("  (no receipt proof with logs captured)");

const failedReceipt = await findReceiptProof("failure");
if (failedReceipt) write("receipt-proof-failure.json", failedReceipt);
else console.log("  (no failed receipt proof captured)");

console.log(`\nhead ${headHeight} ${blockHash.slice(0, 12)}… epoch ${checkpoint.epochId.slice(0, 8)}…`);
console.log(`  pinned ${signers.length} producers that sign this epoch (hash ${checkpoint.validatorsHash.slice(0, 12)}…)`);
console.log(`  the view's own next_bps is the *next* epoch's set (hash ${String(view.inner_lite.next_bp_hash).slice(0, 12)}…)`);
