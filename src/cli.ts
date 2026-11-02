#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { b58encode } from "./base58.js";
import { makeCheckpoint, parseCheckpoint, type Checkpoint } from "./checkpoint.js";
import { NearRpc } from "./rpc.js";
import { fetchLightClientBlock, fetchSignerSet, resolveHead, type ResolveHeadOptions } from "./trust.js";
import { decodeSuccessValue, verifyReceipt, verifyTransaction } from "./verifier.js";
import { verifyContractState } from "./state.js";
import type { Check, ProvenResult, TrustLevel } from "./types.js";

const args = process.argv.slice(2);
const flag = (name: string, fallback?: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
};
const has = (name: string): boolean => args.includes(`--${name}`);

const rpcUrl = flag("rpc", "https://free.rpc.fastnear.com")!;
const rpcList = (flag("rpcs") ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const asJson = has("json");
const requireAnchor = has("require-anchor");

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

const TRUST_LABEL: Record<TrustLevel, string> = {
  anchored: `${GREEN}anchored${RESET} (pinned validator set)`,
  quorum: `${YELLOW}quorum${RESET} (independent RPCs agree)`,
  "rpc-asserted": `${YELLOW}rpc-asserted${RESET} (single RPC — self-consistent only)`,
};

/** Flags that take the token after them as their value; every other `--flag` is a switch. */
const VALUE_FLAGS = new Set(["rpc", "rpcs", "checkpoint", "out", "network"]);

const positional = args.filter((a, i) => {
  if (a.startsWith("--")) return false;
  const previous = args[i - 1];
  return !(previous?.startsWith("--") && VALUE_FLAGS.has(previous.slice(2)));
});

/** `--checkpoint <file>`, else the checkpoint shipped with the package, else none. */
function loadCheckpoint(): Checkpoint | undefined {
  const explicit = flag("checkpoint");
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`checkpoint not found: ${explicit}`);
    return parseCheckpoint(readFileSync(explicit, "utf8"));
  }
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [
    join(here, "../checkpoints/mainnet.json"),
    join(here, "../../checkpoints/mainnet.json"),
  ]) {
    if (!existsSync(candidate)) continue;
    try {
      return parseCheckpoint(readFileSync(candidate, "utf8"));
    } catch (error) {
      // A stale or legacy pin on disk must never stop the tool from working — it only costs trust.
      console.error(
        `${YELLOW}note${RESET}: ignoring ${candidate}: ${error instanceof Error ? error.message : String(error)}`,
      );
      return undefined;
    }
  }
  return undefined;
}

function rpcOptions(): ResolveHeadOptions {
  return {
    rpcs: rpcList.length ? rpcList : [rpcUrl],
    checkpoint: loadCheckpoint(),
    requireAnchor,
  };
}

function renderChecks(checks: Check[]): string {
  return checks
    .map((c) => {
      const mark = c.ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
      return `  ${mark} ${c.name}${c.detail ? `${DIM} — ${c.detail}${RESET}` : ""}`;
    })
    .join("\n");
}

function render<T>(title: string, result: ProvenResult<T>): void {
  const verdict = result.verified ? `${GREEN}${BOLD}VERIFIED${RESET}` : `${RED}${BOLD}REJECTED${RESET}`;
  console.log("");
  console.log(`${BOLD}${title}${RESET}`);
  console.log(`  rpcs               ${DIM}${rpcList.length ? rpcList.join(", ") : rpcUrl}${RESET}`);
  console.log(`  trust              ${TRUST_LABEL[result.trust]}`);
  console.log(`  light client head  ${result.head.height} (${result.head.approvedStakePercent}% of stake signed)`);
  for (const note of result.notes) console.log(`  ${DIM}note: ${note}${RESET}`);
  console.log(renderChecks(result.checks));
  console.log("");
  console.log(`  ${verdict}`);
  console.log("");
}

const asResult = <T>(result: ProvenResult<T>) => ({
  verified: result.verified,
  trust: result.trust,
  notes: result.notes,
  head: result.head,
  checks: result.checks,
});

async function cmdTx(hash: string, signer: string): Promise<number> {
  const result = await verifyTransaction(hash, signer, rpcOptions());
  if (asJson) {
    process.stdout.write(JSON.stringify({ ...asResult(result), outcome: result.value.outcome }, null, 2));
  } else {
    render(`transaction ${hash}`, result);
    console.log(`  executed at   block ${result.value.height}`);
    console.log(`  status        ${Object.keys(result.value.outcome.status)[0]}`);
    const value = decodeSuccessValue(result.value.outcome);
    if (value !== null) console.log(`  return value  ${DIM}${value}${RESET}`);
    console.log("");
  }
  return result.verified ? 0 : 1;
}

async function cmdReceipt(receiptId: string, receiverId: string): Promise<number> {
  const result = await verifyReceipt(receiptId, receiverId, rpcOptions());
  if (asJson) {
    process.stdout.write(JSON.stringify({ ...asResult(result), outcome: result.value.outcome }, null, 2));
  } else {
    render(`receipt ${receiptId}`, result);
    console.log(`  executed by   ${receiverId} at block ${result.value.height}`);
    console.log(`  status        ${Object.keys(result.value.outcome.status)[0]}`);
    const logs = result.value.outcome.logs ?? [];
    if (logs.length) console.log(`  logs          ${logs.length}`);
    const value = decodeSuccessValue(result.value.outcome);
    if (value !== null) console.log(`  return value  ${DIM}${value}${RESET}`);
    console.log("");
  }
  return result.verified ? 0 : 1;
}

async function cmdState(accountId: string, key: string): Promise<number> {
  const keyBytes = has("key-base64")
    ? Uint8Array.from(Buffer.from(key, "base64"))
    : new TextEncoder().encode(key);  const result = await verifyContractState(accountId, keyBytes, rpcOptions());
  if (asJson) {
    process.stdout.write(
      JSON.stringify(
        {
          verified: result.verified,
          trust: result.trust,
          notes: result.notes,
          head: result.head,
          checks: result.checks,
          state: {
            accountId: result.value.accountId,
            key: Buffer.from(result.value.key).toString("base64"),
            value: result.value.valueText,
            stateRoot: result.value.stateRoot,
            shard: result.value.shard,
            queryBlockHeight: result.value.queryBlockHeight,
          },
        },
        null,
        2,
      ),
    );
  } else {
    render(`contract storage ${accountId} ["${key}"]`, result);
    console.log(`  value         ${result.value.valueText ?? "(absent)"}`);
    console.log(`  state root    ${result.value.stateRoot}`);
    console.log(`  shard         ${result.value.shard ?? "not located"} · block ${result.value.rootBlockHeight}`);
    console.log("");
  }
  return result.verified ? 0 : 1;
}

async function cmdHead(): Promise<number> {
  const resolved = await resolveHead(rpcOptions());
  const result: ProvenResult<null> = {
    verified: resolved.checks.every((c) => c.ok),
    value: null,
    checks: resolved.checks,
    trust: resolved.trust,
    notes: resolved.notes,
    head: {
      height: resolved.head.height,
      blockHash: b58encode(resolved.head.blockHash),
      approvedStakePercent: resolved.head.approvedStakePercent,
    },
  };
  if (asJson) {
    process.stdout.write(
      JSON.stringify(
        { verified: result.verified, trust: result.trust, notes: result.notes, head: result.head, checks: result.checks },
        null,
        2,
      ),
    );
  } else {
    render("light client head", result);
  }
  return result.verified ? 0 : 1;
}

async function cmdCheckpoint(): Promise<number> {
  const rpc = new NearRpc(rpcUrl);
  const view = await fetchLightClientBlock(rpc);
  // Pin the producers that sign this epoch (the previous epoch's `next_bps`), not the ones the
  // view carries — those sign the *next* epoch and would mis-attribute every moved validator.
  const signers = await fetchSignerSet(rpc, view.inner_lite.epoch_id, Number(view.inner_lite.height));
  if (!signers) {
    console.error(
      `could not obtain the producer set that signs epoch ${view.inner_lite.epoch_id.slice(0, 8)}…; nothing was written`,
    );
    return 1;
  }
  const checkpoint = makeCheckpoint(view, signers, {
    network: flag("network", "mainnet")!,
    sourceRpc: rpcUrl,
  });
  const out = flag("out");
  if (out) {
    writeFileSync(resolve(out), `${JSON.stringify(checkpoint, null, 2)}\n`);
    console.log(`wrote ${out}`);
    console.log(`  epoch  ${checkpoint.epochId}`);
    console.log(`  head   ${checkpoint.height} ${checkpoint.blockHash}`);
    console.log(`  pinned ${checkpoint.validators.length} producers that sign this epoch, hash ${checkpoint.validatorsHash}`);
  } else {
    process.stdout.write(`${JSON.stringify(checkpoint, null, 2)}\n`);
  }
  return 0;
}

async function cmdFind(height: number): Promise<number> {
  if (!Number.isFinite(height) || height <= 0) {
    console.error("find needs a block height: proven find <height>");
    return 2;
  }
  const tx = await new NearRpc(rpcUrl).findTransaction(height);
  if (!tx) {
    console.log(`no transaction found at height ${height}`);
    return 1;
  }
  console.log(`${tx.hash} ${tx.signer}`);
  return 0;
}

const USAGE = `proven — the NEAR RPC you don't have to trust

  proven tx <hash> <signer>    verify a transaction's outcome client-side
  proven receipt <id> <acct>   verify a receipt / contract-call outcome client-side
  proven state <acct> <key>    verify a contract's stored value with a trie proof
  proven head                  verify the network's current light client head
  proven checkpoint            pin the current block-producer set (enables "anchored" trust)
  proven find <height>         print a transaction at a height (handy for demos)

options
  --rpc <url>                  any NEAR RPC (default https://free.rpc.fastnear.com)
  --rpcs <a,b,...>             two or more independent RPCs enables "quorum" trust
  --checkpoint <file>          pinned checkpoint (default: ./checkpoints/mainnet.json)
  --require-anchor             fail unless a checkpoint applies (no silent downgrade)
  --key-base64                 treat the storage key as base64 instead of utf8
  --json                       machine-readable output`;

async function main(): Promise<number> {
  const [command, a, b] = positional;
  switch (command) {
    case "tx":
      if (!a || !b) {
        console.error("usage: proven tx <transaction_hash> <signer_id> [--rpc url] [--json]");
        return 2;
      }
      return cmdTx(a, b);
    case "receipt":
      if (!a || !b) {
        console.error("usage: proven receipt <receipt_id> <receiver_id> [--rpc url] [--json]");
        return 2;
      }
      return cmdReceipt(a, b);
    case "state":
      if (!a || !b) {
        console.error("usage: proven state <account_id> <storage_key> [--key-base64] [--rpc url]");
        return 2;
      }
      return cmdState(a, b);
    case "head":
      return cmdHead();
    case "checkpoint":
      return cmdCheckpoint();
    case "find":
      return cmdFind(Number(a));
    default:
      console.log(USAGE);
      return command ? 2 : 0;
  }
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(`\n${RED}error${RESET}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  },
);
