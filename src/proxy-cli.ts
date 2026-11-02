#!/usr/bin/env node
// Runs the verifying proxy. Configure with environment variables so it can be deployed as-is
// (Render/Railway/Fly):
//
//   UPSTREAM_RPC=https://free.rpc.fastnear.com
//   PROVEN_CHECKPOINT=checkpoints/mainnet.json
//   PROVEN_STRICT=0
//   PORT=8080
import { createProvenProxy, loadCheckpoint } from "./proxy.js";
import { writeFileSync } from "node:fs";

const port = Number(process.env.PORT ?? 8080);
const upstream = (process.env.UPSTREAM_RPC ?? "https://free.rpc.fastnear.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const checkpointPath = process.env.PROVEN_CHECKPOINT ?? "checkpoints/mainnet.json";
const checkpoint = loadCheckpoint(checkpointPath);
const strict = process.env.PROVEN_STRICT === "1" || process.env.PROVEN_STRICT === "true";

const proxy = createProvenProxy({
  upstream,
  checkpoint,
  strict,
  // Persist a rolled pin: a restart after an epoch boundary would otherwise fall back to a pin that
  // has already expired, and trust would drop until someone re-pinned by hand.
  onRolled: (rolled) => {
    try {
      writeFileSync(checkpointPath, `${JSON.stringify(rolled, null, 2)}\n`);
    } catch (error) {
      console.warn(`proven: could not persist the rolled pin: ${error instanceof Error ? error.message : String(error)}`);
    }
  },
});

proxy.listen(port).then(() => {
  console.log(`proven proxy listening on :${port}`);
  console.log(`  upstream   ${upstream.join(", ")}`);
  console.log(`  checkpoint ${checkpoint ? `epoch ${checkpoint.epochId.slice(0, 8)}… (${checkpoint.validators.length} producers)` : "none"}`);
  console.log(`  mode       ${strict ? "strict (unverifiable methods are refused)" : "observe (everything is forwarded, verdicts in headers)"}`);
});
