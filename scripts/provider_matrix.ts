// Which public NEAR RPCs can a verifier actually use?
//
//   npx tsx scripts/provider_matrix.ts
//
// A verifier needs three things from a provider: it must answer `next_light_client_block` (the head
// that proofs are checked against), it must serve `light_client_proof` (the proof itself), and for a
// browser it must send CORS headers. This probes the endpoints listed on docs.near.org/api/rpc/providers.
import { b58encode } from "../src/base58.js";
import { lightClientBlockHash } from "../src/light-client.js";
import { NearRpc } from "../src/rpc.js";

const BOOTSTRAP = "https://free.rpc.fastnear.com";

const ENDPOINTS = [
  "https://free.rpc.fastnear.com",
  "https://archival-rpc.mainnet.near.org",
  "https://rpc.mainnet.near.org",
  "https://1rpc.io/near",
  "https://near.drpc.org",
  "https://near.blockpi.network/v1/rpc/public",
  "https://rpc.intea.rs",
  "https://rpc.shitzuapes.xyz",
  "https://api.zan.top/node/v1/near/mainnet",
  "https://rpc.ankr.com/near",
];

async function post(
  url: string,
  method: string,
  params: unknown,
): Promise<{ result?: any; error?: any; cors?: string | null }> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://example.com" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "probe", method, params }),
    signal: AbortSignal.timeout(20_000),
  });
  const body: any = await response.json().catch(() => ({}));
  return { ...body, cors: response.headers.get("access-control-allow-origin") };
}

/** Turns a JSON-RPC envelope into a short verdict for the table. */
function verdict(body: { result?: any; error?: any }): string {
  if (body.result !== undefined && body.result !== null) return "yes";
  const message = String(
    body.error?.cause?.name ?? body.error?.message ?? body.error?.name ?? JSON.stringify(body.error ?? ""),
  ).replace(/"/g, "");
  if (/not available|not found|MethodNotFound|-32601|does not exist|unsupported|not supported|apikey/i.test(message)) {
    return `no (${message.slice(0, 40)})`;
  }
  return `error (${message.slice(0, 40)})`;
}

// Ground truth from a provider known to work.
const bootstrap = new NearRpc(BOOTSTRAP);
const final = await bootstrap.finalBlock();
const head = Number(final.header.height);
const anchor = await bootstrap.block(head - 3);
const view: any = await bootstrap.nextLightClientBlock(anchor.header.hash);
const headHash = b58encode(lightClientBlockHash(view));

let sample: { hash: string; signer: string } | null = null;
for (let back = 8; back < 40 && !sample; back++) sample = await bootstrap.findTransaction(head - back);
if (!sample) throw new Error("no sample transaction");
const tx = sample;

console.log(`head ${head} (light client ${view.inner_lite.height}), sample tx ${tx.hash}\n`);
console.log(
  `${"endpoint".padEnd(46)} ${"alive".padEnd(6)} ${"next_light_client_block".padEnd(38)} ${"proof".padEnd(24)} cors`,
);
console.log("-".repeat(140));

for (const url of ENDPOINTS) {
  let alive = "no";
  let nlb = "-";
  let proof = "-";
  let cors: string | null = null;
  try {
    const block = await post(url, "block", { finality: "final" });
    alive = block.result ? "yes" : verdict(block);
    cors = block.cors;
  } catch {
    alive = "no";
  }
  if (alive === "yes") {
    nlb = await post(url, "next_light_client_block", { last_block_hash: anchor.header.hash })
      .then(verdict)
      .catch((error: Error) => `error (${error.message.slice(0, 34)})`);
    proof = await post(url, "light_client_proof", {
      type: "transaction",
      light_client_head: headHash,
      transaction_hash: tx.hash,
      sender_id: tx.signer,
    })
      .then(verdict)
      .catch((error: Error) => `error (${error.message.slice(0, 34)})`);
  }
  console.log(`${url.padEnd(46)} ${String(alive).padEnd(6)} ${nlb.padEnd(38)} ${proof.padEnd(24)} ${cors ?? "-"}`);
}
