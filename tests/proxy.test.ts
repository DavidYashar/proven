// The proxy's contract: an honest upstream is marked verified, a lying one is caught, and strict
// mode refuses what cannot be verified at all.
//
//   npx tsx tests/proxy.test.ts        (needs network for the honest case)
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { createProvenProxy, loadCheckpoint } from "../src/proxy.js";

// Free public endpoints drop requests under load, so the tests use the same failover list the
// deployment does. Only these two answer `next_light_client_block`.
const UPSTREAMS = (process.env.UPSTREAM_RPC ?? "https://free.rpc.fastnear.com,https://rpc.mainnet.near.org")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const UPSTREAM = UPSTREAMS[0];
const checkpoint = loadCheckpoint(fileURLToPath(new URL("../checkpoints/mainnet.json", import.meta.url)));
if (!checkpoint) throw new Error("test needs checkpoints/mainnet.json (run `npm run checkpoint`)");

const listen = (server: Server): Promise<number> =>
  new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(typeof address === "object" && address ? address.port : 0);
    });
  });

async function rpc(url: string, method: string, params: unknown): Promise<{ status: number; headers: Headers; body: any }> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "test", method, params }),
  });
  return { status: response.status, headers: response.headers, body: await response.json() };
}

/** Tries each provider in turn, because a free endpoint will return an error now and then. */
async function rpcAny(method: string, params: unknown): Promise<{ status: number; headers: Headers; body: any }> {
  let last: any;
  for (let attempt = 0; attempt < 3; attempt++) {
    for (const url of UPSTREAMS) {
      const res = await rpc(url, method, params).catch((error) => ({
        status: 0,
        headers: new Headers(),
        body: { error: { message: String(error) } },
      }));
      if (res.body?.result !== undefined) return res;
      last = res;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`no provider answered ${method}: ${JSON.stringify(last?.body?.error ?? last?.body).slice(0, 200)}`);
}

/** A near transaction to test with, found near the head. */
async function sampleTransaction(): Promise<{ hash: string; signer: string }> {
  const head = await rpcAny("block", { finality: "final" });
  for (let back = 6; back < 40; back++) {
    const block = await rpcAny("block", { block_id: Number(head.body.result.header.height) - back });
    const chunks = block.body.result?.chunks;
    if (!chunks) continue;
    for (const chunkInfo of chunks) {
      try {
        const chunk = await rpcAny("chunk", { chunk_id: chunkInfo.chunk_hash });
        const tx = (chunk.body.result?.transactions ?? []).find((t: any) => t.signer_id);
        if (tx) return { hash: tx.hash, signer: tx.signer_id };
      } catch {
        continue;
      }
    }
  }
  throw new Error("no sample transaction found");
}

/** An upstream that rewrites the transaction outcome on its way back. */
function startLiar(): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      const body = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
      const json: any = await body.json();
      if (json.result?.transaction_outcome?.outcome) {
        json.result.transaction_outcome.outcome.executor_id = `${json.result.transaction_outcome.outcome.executor_id}-attacker`;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    }),
  );
}

/** An upstream that rewrites the *receipt* outcome, leaving the transaction outcome honest. */
function startReceiptLiar(): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      const body = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
      const json: any = await body.json();
      const receipts = json.result?.receipts_outcome;
      if (Array.isArray(receipts) && receipts.length > 0) {
        const last = receipts[receipts.length - 1];
        last.outcome.executor_id = `${last.outcome.executor_id}-attacker`;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    }),
  );
}

test("honest upstream: tx status is verified and tagged anchored", async () => {
  const proxy = createProvenProxy({ upstream: UPSTREAMS, checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "EXPERIMENTAL_tx_status", {
      tx_hash: tx.hash,
      sender_account_id: tx.signer,
      wait_until: "FINAL",
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-proven-verified"), "true", JSON.stringify(response.body).slice(0, 200));
    assert.equal(response.headers.get("x-proven-trust"), "anchored");
    assert.equal(response.body.result.transaction_outcome.outcome.executor_id, tx.signer);
  } finally {
    server.close();
  }
});

test("lying upstream: a rewritten outcome is refused, not forwarded", async () => {
  const liar = await startLiar();
  const proxy = createProvenProxy({ upstream: [liar.url, ...UPSTREAMS], checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "EXPERIMENTAL_tx_status", {
      tx_hash: tx.hash,
      sender_account_id: tx.signer,
    });
    assert.equal(response.headers.get("x-proven-verified"), "false");
    assert.ok(response.body.error, "the payload must not be handed back");
    assert.match(response.body.error.message, /verification failed/);
  } finally {
    server.close();
    liar.close();
  }
});

test("lying upstream: a rewritten receipt is refused, not forwarded", async () => {
  const liar = await startReceiptLiar();
  const proxy = createProvenProxy({ upstream: [liar.url, ...UPSTREAMS], checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "EXPERIMENTAL_tx_status", {
      tx_hash: tx.hash,
      sender_account_id: tx.signer,
    });
    // The transaction outcome is honest here; only the receipt — where the contract-call result lives —
    // is rewritten. That must not pass.
    assert.equal(response.headers.get("x-proven-verified"), "false");
    assert.ok(response.body.error, "the payload must not be handed back");
  } finally {
    server.close();
    liar.close();
  }
});

/** An upstream that forwards honestly but rewrites one field of a tx_status answer. */
function startModeLiar(): Promise<{ url: string; set: (mode: string) => void; close: () => void }> {
  let mode = "none";
  const b64 = (s: string) => Buffer.from(s).toString("base64");
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      const method = String(JSON.parse(raw || "{}")?.method ?? "");
      if ((mode === "no-proofs" || mode === "tx-hash-no-proofs") && method.endsWith("light_client_proof")) {
        // A node that will not serve proofs: not evidence of anything, so it must not read as a lie.
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: "x", error: { code: -32000, message: "proofs disabled" } }));
        return;
      }
      const body = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
      const json: any = await body.json();
      const x = json.result;
      if (x && Array.isArray(x.receipts_outcome)) {
        if (mode === "status") x.status = { SuccessValue: b64('"pwned"') };
        if (mode === "first-receipt-status" && x.receipts_outcome[0]) {
          x.receipts_outcome[0].outcome.status = { SuccessValue: b64('"pwned"') };
        }
        if (mode === "log") {
          const target = x.receipts_outcome[0] ?? x.receipts_outcome.at(-1);
          target.outcome.logs = [
            'EVENT_JSON:{"standard":"nep141","event":"ft_transfer","data":[{"new_owner_id":"attacker.near"}]}',
          ];
        }
        if (mode === "drop-receipt") x.receipts_outcome.splice(0, 1);
        if ((mode === "tx-hash" || mode === "tx-hash-no-proofs") && x.transaction?.hash) {
          x.transaction.hash = [...x.transaction.hash].reverse().join("");
        }
        if (mode === "pending") {
          // What the node returns right after inclusion: the transaction outcome exists, but no
          // receipt has executed yet, and `final_execution_status` says so. (Nodes build
          // `receipts_outcome` by walking down from the transaction, so a pending answer is always a
          // truncated tree — never a child without its parent.)
          x.final_execution_status = "INCLUDED";
          x.receipts_outcome = [];
        }
        if (mode === "pending-padded" && x.receipts_outcome[0]) {
          // "Still executing" must not become a hiding place: a receipt the proven tree never names
          // is padding whether or not the transaction has settled.
          const fake = structuredClone(x.receipts_outcome[0]);
          fake.id = "11111111111111111111111111111111";
          fake.outcome.executor_id = "attacker.near";
          x.final_execution_status = "INCLUDED";
          x.receipts_outcome = [fake];
        }
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ url: `http://127.0.0.1:${port}`, set: (next: string) => (mode = next), close: () => server.close() });
    }),
  );
}

test("a forged status, log, hash or dropped/padded receipt is refused", async () => {
  const liar = await startModeLiar();
  const proxy = createProvenProxy({ upstream: [liar.url, ...UPSTREAMS], checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const port = (server.address() as any).port;
    for (const mode of ["none", "status", "log", "tx-hash", "drop-receipt", "pending", "pending-padded"]) {
      liar.set(mode);
      const response = await rpc(`http://127.0.0.1:${port}`, "EXPERIMENTAL_tx_status", {
        tx_hash: tx.hash,
        sender_account_id: tx.signer,
      });
      const verdict = response.headers.get("x-proven-verified");
      if (mode === "none") assert.equal(verdict, "true", `honest pass-through: ${JSON.stringify(response.body).slice(0, 160)}`);
      // A dropped receipt is a forgery once settled, but merely "cannot judge" while the transaction
      // is still executing — that distinction is what a wallet polling a fresh tx hits first.
      else if (mode === "pending") {
        assert.equal(verdict, "unverified", `pending must not be an accusation: ${JSON.stringify(response.body).slice(0, 160)}`);
        assert.ok(response.body.result, "the payload must still be returned");
        assert.equal(response.body.error, undefined);
      } else assert.equal(verdict, "false", `${mode} must not verify`);
    }
  } finally {
    server.close();
    liar.close();
  }
});

test("view_state: a failed proof is not reported as a proven-absent key", async () => {
  // The library returns value=null both for "absent" and for "the proof failed", so the proxy has to
  // consult `verified` first. This is the regression that made an emptied payload look proven.
  // Needs the network: the proof itself is real, only the payload is emptied.
  const liar = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      const body = await fetch(UPSTREAM, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
      const json: any = await body.json();
      if (json.result?.values) {
        json.result.values = []; // claim the key is absent while keeping the proof for it
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    });
  });
  const port: number = await new Promise((resolve) => {
    liar.listen(0, "127.0.0.1", () => resolve((liar.address() as any).port));
  });
  const proxy = createProvenProxy({ upstream: [`http://127.0.0.1:${port}`], checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const proxyPort = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${proxyPort}`, "query", {
      request_type: "view_state",
      account_id: "mpc-prover-0_4_12.bridge.near",
      prefix_base64: Buffer.from("STATE").toString("base64"),
      include_proof: true,
      finality: "final",
    });
    assert.equal(response.headers.get("x-proven-verified"), "false", JSON.stringify(response.body).slice(0, 200));
  } finally {
    server.close();
    liar.close();
  }
});

test("strict mode refuses methods that have no proof primitive", async () => {
  const proxy = createProvenProxy({ upstream: UPSTREAMS, checkpoint, strict: true });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "query", {
      request_type: "view_account",
      account_id: "sweat-relayer.near",
      finality: "final",
    });
    assert.equal(response.headers.get("x-proven-verified"), "rejected");
    assert.equal(response.body.error.code, -32001);
  } finally {
    server.close();
  }
});

test("no proof served is 'cannot judge' — forwarded when observing, refused when strict", async () => {
  // Needs the network: the head and the payload are real, only the proof endpoint is switched off.
  const liar = await startModeLiar();
  liar.set("no-proofs");
  const observing = createProvenProxy({ upstream: [liar.url], checkpoint });
  const strict = createProvenProxy({ upstream: [liar.url], checkpoint, strict: true });
  const observingServer = await observing.listen(0, "127.0.0.1");
  const strictServer = await strict.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const params = { tx_hash: tx.hash, sender_account_id: tx.signer };

    const open = await rpc(`http://127.0.0.1:${(observingServer.address() as any).port}`, "EXPERIMENTAL_tx_status", params);
    assert.equal(open.headers.get("x-proven-verified"), "unverified", JSON.stringify(open.body).slice(0, 200));
    assert.ok(open.body.result, "observing mode hands the payload back with an honest header");
    assert.match(decodeURIComponent(open.headers.get("x-proven-detail") ?? ""), /no proof/);

    const closed = await rpc(`http://127.0.0.1:${(strictServer.address() as any).port}`, "EXPERIMENTAL_tx_status", params);
    assert.equal(closed.headers.get("x-proven-verified"), "rejected", JSON.stringify(closed.body).slice(0, 200));
    assert.equal(closed.body.error?.code, -32001);
    assert.equal(closed.body.result, undefined, "strict mode must not hand back an unproven payload");

    // A forgery is still a forgery without a proof: identity needs none.
    liar.set("tx-hash-no-proofs");
    const forged = await rpc(`http://127.0.0.1:${(observingServer.address() as any).port}`, "EXPERIMENTAL_tx_status", params);
    assert.equal(forged.headers.get("x-proven-verified"), "false");
    assert.equal(forged.body.error?.code, -32002);
    assert.match(forged.body.error?.message, /transaction\.hash does not match/);
    assert.equal(forged.body.result, undefined);
    assert.equal(observing.counters.unverified, 1);
    assert.equal(observing.counters.failed, 1);
    assert.equal(strict.counters.rejected, 1);
  } finally {
    observingServer.close();
    strictServer.close();
    liar.close();
  }
});

test("strict mode refuses a pending transaction instead of forwarding it", async () => {
  const liar = await startModeLiar();
  liar.set("pending");
  const proxy = createProvenProxy({ upstream: [liar.url, ...UPSTREAMS], checkpoint, strict: true });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const tx = await sampleTransaction();
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "EXPERIMENTAL_tx_status", {
      tx_hash: tx.hash,
      sender_account_id: tx.signer,
    });
    assert.equal(response.headers.get("x-proven-verified"), "rejected", JSON.stringify(response.body).slice(0, 200));
    assert.equal(response.body.error?.code, -32001);
    assert.equal(response.body.result, undefined);
  } finally {
    server.close();
    liar.close();
  }
});

test("status page reports the live head and counters", async () => {
  const proxy = createProvenProxy({ upstream: UPSTREAMS, checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const port = (server.address() as any).port;
    const response = await fetch(`http://127.0.0.1:${port}/status`);
    const body: any = await response.json();
    assert.equal(body.service, "proven proxy");
    assert.ok(body.verifiable.some((v: string) => v.startsWith("query")));
    assert.ok(typeof body.counters.requests === "number");
    assert.ok(typeof body.counters.unverified === "number", "unverified answers are counted");
    // Free endpoints rate-limit under a full suite; the honest answers are "a head" or "this is why
    // there is no head yet", never a silent zero.
    if ("error" in body.head) assert.ok(String(body.head.error).length > 0);
    else assert.ok(body.head.height > 0);
  } finally {
    server.close();
  }
});

test("observing mode forwards unverifiable methods with an honest header", async () => {
  const proxy = createProvenProxy({ upstream: UPSTREAMS, checkpoint });
  const server = await proxy.listen(0, "127.0.0.1");
  try {
    const port = (server.address() as any).port;
    const response = await rpc(`http://127.0.0.1:${port}`, "status", {});
    assert.equal(response.headers.get("x-proven-verified"), "unverified");
    assert.equal(response.body.result?.chain_id, "mainnet");
  } finally {
    server.close();
  }
});
