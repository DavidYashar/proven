// One-off check of the browser tamper layer without the browser: the forged validator set must be
// caught by the pinned checkpoint on the validator set itself, not on a mismatched epoch.
import { readFileSync } from "node:fs";
import { createTamperedFetch } from "../web/src/tamper.js";
import { NearRpc } from "../src/rpc.js";
import { resolveHead } from "../src/trust.js";
import { parseCheckpoint } from "../src/checkpoint.js";

const checkpoint = parseCheckpoint(readFileSync("checkpoints/mainnet.json", "utf8"));
const url = "https://free.rpc.fastnear.com";

for (const lie of ["forge", "finality"] as const) {
  const events: string[] = [];
  const rpc = new NearRpc({ url, fetchImpl: createTamperedFetch(lie, (m) => events.push(m)) });
  const loose = await resolveHead({ rpcs: [rpc], checkpoint });
  const strict = await resolveHead({ rpcs: [new NearRpc({ url, fetchImpl: createTamperedFetch(lie) })], checkpoint, requireAnchor: true });
  console.log(`\n${lie}: ${events.join(" | ")}`);
  console.log(`  no anchor required → trust ${loose.trust}, verified=${loose.checks.every((c) => c.ok)}`);
  for (const note of loose.notes) console.log(`    note: ${note}`);
  const failed = strict.checks.filter((c) => !c.ok);
  console.log(`  anchor required    → trust ${strict.trust}, verified=${strict.checks.every((c) => c.ok)}`);
  for (const f of failed) console.log(`    ✗ ${f.name} — ${f.detail}`);
}
