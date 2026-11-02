// Demo / test: a lying RPC cannot fool `proven`.
//
//   npx tsx tests/demo.ts
//
// Spins up a proxy in front of a real NEAR RPC that tampers with responses, then asks the
// verifier to check the same transaction through all three endpoints.
import { createServer, type Server } from "node:http";
import { verifyTransaction } from "../src/verifier.js";

const UPSTREAM = process.env.UPSTREAM_RPC ?? "https://free.rpc.fastnear.com";

type Lie = "none" | "outcome" | "finality";

async function upstream(method: string, params: unknown): Promise<any> {
  const response = await fetch(UPSTREAM, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "demo", method, params }),
  });
  return response.json();
}

/** Applies an attack to a JSON-RPC response body. */
function applyLie(body: any, lie: Lie): any {
  if (lie === "none") return body;
  if (lie === "finality" && body.result?.inner_lite) {
    // Pretend a block is final even though nobody signed it.
    return { ...body, result: { ...body.result, approvals_after_next: body.result.approvals_after_next.map(() => null) } };
  }
  if (lie === "outcome" && body.result?.outcome_proof?.outcome) {
    // Rewrite the outcome (e.g. claim gas was burned for a different executor).
    return {
      ...body,
      result: {
        ...body.result,
        outcome_proof: {
          ...body.result.outcome_proof,
          outcome: { ...body.result.outcome_proof.outcome, executor_id: `${body.result.outcome_proof.outcome.executor_id}x` },
        },
      },
    };
  }
  return body;
}

function startLiar(lie: Lie, port: number): Promise<Server> {
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      try {
        const { method, params } = JSON.parse(raw || "{}");
        const body = await upstream(method, params);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(applyLie(body, lie)));
      } catch (error) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: String(error) } }));
      }
    });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

async function pickSampleTransaction(): Promise<{ hash: string; signer: string }> {
  const head = await upstream("block", { finality: "final" });
  for (let back = 6; back < 20; back++) {
    const block = await upstream("block", { block_id: Number(head.result.header.height) - back });
    for (let shard = 0; shard < block.result.chunks.length; shard++) {
      let chunk;
      try {
        chunk = await upstream("chunk", { block_id: block.result.header.hash, shard_id: shard });
      } catch {
        continue;
      }
      const tx = (chunk.result?.transactions ?? []).find((t: any) => t.signer_id);
      if (tx) return { hash: tx.hash, signer: tx.signer_id };
    }
  }
  throw new Error("could not find a sample transaction");
}

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

async function run(lie: Lie, label: string, tx: { hash: string; signer: string }, port: number) {
  const server = await startLiar(lie, port);
  try {
    const result = await verifyTransaction(tx.hash, tx.signer, { rpc: `http://127.0.0.1:${port}` });
    const failed = result.checks.filter((c) => !c.ok);
    const verdict = result.verified ? `${GREEN}accepted${RESET}` : `${RED}rejected${RESET}`;
    console.log(`${label.padEnd(34)} → ${verdict}`);
    for (const check of failed) console.log(`    ${RED}✗${RESET} ${check.name}`);
    return result.verified;
  } finally {
    server.close();
  }
}

async function main() {
  console.log(`${DIM}upstream: ${UPSTREAM}${RESET}`);
  const tx = await pickSampleTransaction();
  console.log(`${DIM}sample:   ${tx.hash} (${tx.signer})${RESET}\n`);

  const honest = await run("none", "honest RPC", tx, 8711);
  const fakeOutcome = await run("outcome", "RPC that rewrites the outcome", tx, 8712);
  const fakeFinality = await run("finality", "RPC that fakes finality", tx, 8713);

  const ok = honest && !fakeOutcome && !fakeFinality;
  console.log(`\nhonest verified: ${honest}`);
  console.log(`outcome forgery caught: ${!fakeOutcome}`);
  console.log(`finality forgery caught: ${!fakeFinality}`);
  console.log(ok ? `\n${GREEN}demo passed${RESET}` : `\n${RED}demo failed${RESET}`);
  process.exit(ok ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

export { applyLie };
