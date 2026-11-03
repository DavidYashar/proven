import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { type Checkpoint } from "../src/checkpoint.js";
import { createProvenProxy } from "../src/proxy.js";
import type { LightClientBlockView, LightClientProof } from "../src/types.js";

const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8")) as T;
const checkpoint = fixture<Checkpoint>("checkpoint");
const view = fixture<LightClientBlockView>("light-client-block");
const tx = fixture<{ txHash: string; signer: string; proof: LightClientProof }>("tx-proof-success");
type OutcomeEntry = { id: string; outcome: LightClientProof["outcome_proof"]["outcome"] };
type Payload = {
  transaction: { hash: string; signer_id: string };
  transaction_outcome: OutcomeEntry;
  receipts_outcome: OutcomeEntry[];
  final_execution_status: string;
  status: { SuccessValue: string };
};

const listen = (server: Server): Promise<string> => new Promise((resolve) => {
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    resolve(`http://127.0.0.1:${address.port}`);
  });
});
const close = (server: Server): Promise<void> => new Promise((resolve, reject) => {
  server.close((error) => error ? reject(error) : resolve());
  server.closeAllConnections();
});

async function harness(t: TestContext, options: {
  strict?: boolean;
  noProof?: boolean;
  mutate?: (payload: Payload) => void;
} = {}) {
  let proofRequests = 0;
  const upstream = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk: Buffer) => { raw += chunk.toString(); });
    req.on("end", () => {
      const request = JSON.parse(raw) as { id: unknown; method: string; params: { type?: string } };
      const reply = (body: { result: unknown } | { error: { code: number; message: string } }) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, ...body }));
      };
      if (request.method === "block") {
        reply({ result: { header: { height: view.inner_lite.height + 3, hash: checkpoint.blockHash } } });
      } else if (request.method === "next_light_client_block") {
        reply({ result: view });
      } else if (request.method.endsWith("light_client_proof")) {
        proofRequests++;
        if (options.noProof || request.params.type === "receipt") {
          reply({ error: { code: -32000, message: "proof unavailable" } });
        } else reply({ result: tx.proof });
      } else if (request.method === "tx") {
        // The transaction's signed outcome names a receipt not yet present in this snapshot.
        const payload: Payload = {
          transaction: { hash: tx.txHash, signer_id: tx.signer },
          transaction_outcome: structuredClone(tx.proof.outcome_proof),
          receipts_outcome: [],
          final_execution_status: "INCLUDED",
          status: { SuccessValue: "" },
        };
        options.mutate?.(payload);
        reply({ result: payload });
      } else if (request.method === "status") {
        reply({ result: { chain_id: "mainnet" } });
      } else {
        reply({ error: { code: -32601, message: `unexpected fixture method: ${request.method}` } });
      }
    });
  });
  const url = await listen(upstream);
  t.after(() => close(upstream));
  const proxy = createProvenProxy({ upstream: url, checkpoint, strict: options.strict });
  const server = await proxy.listen(0, "127.0.0.1");
  t.after(() => close(server));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    counters: proxy.counters,
    proofRequests: () => proofRequests,
    async request(method = "tx") {
      const response = await fetch(`http://127.0.0.1:${address.port}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: "offline-test", method,
          params: { tx_hash: tx.txHash, sender_account_id: tx.signer, wait_until: "NONE" },
        }),
      });
      const body = await response.json() as { id: string; result?: Payload; error?: { code: number; message: string } };
      assert.equal(response.status, 200);
      assert.equal(body.id, "offline-test");
      return { verdict: response.headers.get("x-proven-verified"), body };
    },
  };
}

test("pending snapshots are unverified when observing and rejected when strict", async (t) => {
  for (const status of ["INCLUDED", "EXECUTED_OPTIMISTIC"]) {
    for (const strict of [false, true]) {
      const proxy = await harness(t, { strict, mutate: (payload) => { payload.final_execution_status = status; } });
      const response = await proxy.request();
      assert.equal(response.verdict, strict ? "rejected" : "unverified");
      assert.equal(proxy.proofRequests(), 1, "the recorded transaction proof must actually be checked");
      assert.equal(response.body.error?.code, strict ? -32001 : undefined);
      assert.equal(Boolean(response.body.result), !strict);
      assert.equal(proxy.counters.failed, 0);
      assert.equal(strict ? proxy.counters.rejected : proxy.counters.unverified, 1);
    }
  }
});

test("settled snapshots cannot omit a receipt committed by the proof", async (t) => {
  for (const status of ["EXECUTED", "FINAL"]) {
    const proxy = await harness(t, { mutate: (payload) => { payload.final_execution_status = status; } });
    const response = await proxy.request();
    assert.equal(response.verdict, "false");
    assert.equal(response.body.error?.code, -32002);
    assert.match(response.body.error?.message ?? "", /is missing from the response/);
    assert.equal(response.body.result, undefined);
  }
});

test("pending status cannot hide an unrelated receipt", async (t) => {
  const proxy = await harness(t, { mutate: (payload) => {
    payload.receipts_outcome.push({ id: tx.txHash, outcome: structuredClone(tx.proof.outcome_proof.outcome) });
  } });
  const response = await proxy.request();
  assert.equal(response.verdict, "false");
  assert.match(response.body.error?.message ?? "", /not part of it/);
  assert.equal(response.body.result, undefined);
});

test("identity contradictions are refused before any unavailable proof is requested", async (t) => {
  const mutations: Array<(payload: Payload) => void> = [
    (payload) => { payload.transaction.hash = "wrong-hash"; },
    (payload) => { payload.transaction.signer_id = "wrong-signer.near"; },
    (payload) => { payload.transaction_outcome.id = "wrong-outcome"; },
  ];
  for (const mutate of mutations) {
    const proxy = await harness(t, { noProof: true, mutate });
    const response = await proxy.request();
    assert.equal(response.verdict, "false");
    assert.equal(response.body.error?.code, -32002);
    assert.equal(response.body.result, undefined);
    assert.equal(proxy.proofRequests(), 0);
  }
});

test("missing transaction proofs are not labelled as contradictions", async (t) => {
  for (const strict of [false, true]) {
    const proxy = await harness(t, { strict, noProof: true });
    const response = await proxy.request();
    assert.equal(response.verdict, strict ? "rejected" : "unverified");
    assert.equal(proxy.proofRequests(), 2, "one retry after refreshing the head");
    assert.equal(response.body.error?.code, strict ? -32001 : undefined);
    assert.equal(Boolean(response.body.result), !strict);
  }
});

test("missing receipt proofs are not labelled as contradictions", async (t) => {
  for (const strict of [false, true]) {
    const proxy = await harness(t, { strict, mutate: (payload) => {
      payload.receipts_outcome.push({
        id: tx.proof.outcome_proof.outcome.receipt_ids[0],
        outcome: { ...structuredClone(tx.proof.outcome_proof.outcome), executor_id: "contract.near" },
      });
    } });
    const response = await proxy.request();
    assert.equal(response.verdict, strict ? "rejected" : "unverified");
    assert.equal(proxy.proofRequests(), 3, "transaction plus two receipt proof attempts");
    assert.equal(response.body.error?.code, strict ? -32001 : undefined);
    assert.equal(Boolean(response.body.result), !strict);
  }
});

test("an outcome contradicting its real proof is refused even while pending", async (t) => {
  const proxy = await harness(t, { mutate: (payload) => { payload.transaction_outcome.outcome.logs = ["forged"]; } });
  const response = await proxy.request();
  assert.equal(response.verdict, "false");
  assert.equal(response.body.error?.code, -32002);
  assert.equal(response.body.result, undefined);
});

test("unsupported methods are counted consistently in both proxy modes", async (t) => {
  for (const strict of [false, true]) {
    const proxy = await harness(t, { strict });
    const response = await proxy.request("status");
    assert.equal(response.verdict, strict ? "rejected" : "unverified");
    assert.equal(strict ? proxy.counters.rejected : proxy.counters.unverified, 1);
    assert.equal(proxy.counters.failed, 0);
  }
});
