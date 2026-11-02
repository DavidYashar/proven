#!/usr/bin/env node
// Runs the verifying proxy. Configure with environment variables so it can be deployed as-is
// (Render/Railway/Fly):
//
//   UPSTREAM_RPC=https://free.rpc.fastnear.com
//   PROVEN_CHECKPOINT=checkpoints/mainnet.json
//   PROVEN_STRICT=0
//   PORT=8080
import { createProvenProxy, loadCheckpoint } from "./proxy.js";

const port = Number(process.env.PORT ?? 8080);
const upstream = (process.env.UPSTREAM_RPC ?? "https://free.rpc.fastnear.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const checkpoint = loadCheckpoint(process.env.PROVEN_CHECKPOINT ?? "checkpoints/mainnet.json");
const strict = process.env.PROVEN_STRICT === "1" || process.env.PROVEN_STRICT === "true";

const proxy = createProvenProxy({ upstream, checkpoint, strict });

proxy.listen(port).then(() => {
  console.log(`proven proxy listening on :${port}`);
  console.log(`  upstream   ${upstream.join(", ")}`);
  console.log(`  checkpoint ${checkpoint ? `epoch ${checkpoint.epochId.slice(0, 8)}… (${checkpoint.validators.length} producers)` : "none"}`);
  console.log(`  mode       ${strict ? "strict (unverifiable methods are refused)" : "observe (everything is forwarded, verdicts in headers)"}`);
});
