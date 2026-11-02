// Latency of the verifying proxy versus talking to the RPC directly.
//
//   npx tsx scripts/bench.ts [--rpc URL] [--proxy URL] [--samples N]
//
// Every request the proxy serves re-resolves the light client head (that is what makes the verdict
// meaningful), so this measures what that costs. The direct numbers are the same call without the
// extra hop and without verification.
import { NearRpc } from "../src/rpc.js";

const arg = (name: string, fallback?: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
};

const RPC = arg("rpc", "https://free.rpc.fastnear.com")!;
const PROXY = arg("proxy", "http://localhost:8080")!;
const SAMPLES = Number(arg("samples", "7"));

const rpc = new NearRpc(RPC);
const final = await rpc.finalBlock();
const head = Number(final.header.height);

let sample: { hash: string; signer: string } | null = null;
for (let back = 8; back < 40 && !sample; back++) sample = await rpc.findTransaction(head - back);
if (!sample) throw new Error("no recent transaction found to benchmark with");

async function time(url: string, method: string, params: unknown): Promise<number> {
  const started = performance.now();
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "bench", method, params }),
  });
  const body: any = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message ?? JSON.stringify(body.error).slice(0, 120)}`);
  return performance.now() - started;
}

function summarize(label: string, samples: number[]): void {
  const sorted = [...samples].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const p90 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.9))];
  console.log(
    `${label.padEnd(34)} median ${median.toFixed(0).padStart(6)} ms   p90 ${p90.toFixed(0).padStart(6)} ms`,
  );
}

async function bench(label: string, url: string, method: string, params: unknown): Promise<void> {
  await time(url, method, params).catch(() => 0); // warm up connections
  const samples: number[] = [];
  for (let i = 0; i < SAMPLES; i++) samples.push(await time(url, method, params));
  summarize(label, samples);
}

const txParams = { tx_hash: sample.hash, sender_account_id: sample.signer };

console.log(`rpc   ${RPC}`);
console.log(`proxy ${PROXY}`);
console.log(`tx    ${sample.hash} (${sample.signer})\n`);

await bench("block           direct", RPC, "block", { finality: "final" });
await bench("block           via proxy", PROXY, "block", { finality: "final" });
await bench("tx_status       direct", RPC, "EXPERIMENTAL_tx_status", txParams);
await bench("tx_status       via proxy", PROXY, "EXPERIMENTAL_tx_status", txParams);

const status = await fetch(`${PROXY}/status`).then((r) => r.json() as any);
console.log(`\nproxy counters: ${JSON.stringify(status.counters)}`);
