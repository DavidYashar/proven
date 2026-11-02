import {
  NearRpc,
  verifyContractState,
  b58encode,
  decodeSuccessValue,
  parseCheckpoint,
  resolveHead,
  validatorsHash,
  verifyTransaction,
  type Check,
  type Checkpoint,
  type ProvenResult,
  type TrustLevel,
} from "../../dist/index.js";
import checkpointJson from "../../checkpoints/mainnet.json";
import { createTamperedFetch, LIES, type Lie } from "./tamper.js";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

const el = {
  rpc: $<HTMLInputElement>("rpc"),
  tx: $<HTMLInputElement>("tx"),
  signer: $<HTMLInputElement>("signer"),
  lie: $<HTMLSelectElement>("lie"),
  lieBlurb: $<HTMLParagraphElement>("lie-blurb"),
  verify: $<HTMLButtonElement>("verify"),
  example: $<HTMLButtonElement>("example"),
  head: $<HTMLButtonElement>("head"),
  verifyState: $<HTMLButtonElement>("verify-state"),
  account: $<HTMLInputElement>("account"),
  storageKey: $<HTMLInputElement>("storage-key"),
  output: $<HTMLElement>("output"),
  badge: $<HTMLElement>("trust-badge"),
  checkpoint: $<HTMLElement>("checkpoint-status"),
  repin: $<HTMLButtonElement>("repin"),
  requireAnchor: $<HTMLInputElement>("require-anchor"),
};

const STORAGE_KEY = "proven.checkpoint.v1";

function loadCheckpoint(): Checkpoint {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return parseCheckpoint(stored);
  } catch {
    /* ignore corrupt storage and fall back to the shipped pin */
  }
  return parseCheckpoint(checkpointJson as unknown as Checkpoint);
}

function saveCheckpoint(value: Checkpoint): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    /* private mode: the pin simply will not persist */
  }
}

let checkpoint: Checkpoint = loadCheckpoint();
let busy = false;
const liveEvents: string[] = [];

// ------------------------------------------------------------------ rendering

const esc = (s: unknown): string =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const TRUST_TEXT: Record<TrustLevel, string> = {
  anchored: "anchored Â· pinned validator set",
  quorum: "quorum Â· independent RPCs agree",
  "rpc-asserted": "rpc-asserted Â· self-consistent only",
};

function setBadge(trust: TrustLevel | "idle" | "failed", ok = true): void {
  // A rejected result must not advertise the trust level it was aiming for.
  const shown = ok && trust !== "failed" ? trust : "failed";
  el.badge.dataset.trust = shown;
  el.badge.textContent = shown === "idle" || shown === "failed" ? shown : TRUST_TEXT[shown];
}

function renderChecks(checks: Check[]): string {
  return `<ul class="checks">${checks
    .map(
      (c) => `<li data-ok="${c.ok}">
        <span class="mark">${c.ok ? "âœ“" : "âœ—"}</span>
        <span><span class="name">${esc(c.name)}</span>${
          c.detail ? `<br /><span class="detail">${esc(c.detail)}</span>` : ""
        }</span>
      </li>`,
    )
    .join("")}</ul>`;
}

function renderResult<T>(title: string, result: ProvenResult<T>, extra: Record<string, string>): void {
  const notes = [...result.notes, ...liveEvents];
  el.output.hidden = false;
  el.output.innerHTML = `
    <h3>${esc(title)}</h3>
    <p class="verdict" data-ok="${result.verified}">${result.verified ? "VERIFIED" : "REJECTED"}</p>
    <div class="meta">
      <span class="k">trust</span><span class="v">${esc(TRUST_TEXT[result.trust])}</span>
      <span class="k">light client head</span><span class="v">${result.head.height} Â· ${result.head.approvedStakePercent}% of staked NEAR signed</span>
      ${Object.entries(extra)
        .map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`)
        .join("")}
    </div>
    ${result.checks.length ? renderChecks(result.checks) : ""}
    ${notes.length ? `<div class="note">${notes.map(esc).join("<br />")}</div>` : ""}
  `;
  setBadge(result.trust, result.verified);
}

function renderHeadOnly(resolved: Awaited<ReturnType<typeof resolveHead>>): void {
  const verified = resolved.checks.every((c) => c.ok);
  el.output.hidden = false;
  el.output.innerHTML = `
    <h3>light client head</h3>
    <p class="verdict" data-ok="${verified}">${verified ? "VERIFIED" : "REJECTED"}</p>
    <div class="meta">
      <span class="k">trust</span><span class="v">${esc(TRUST_TEXT[resolved.trust])}</span>
      <span class="k">height</span><span class="v">${resolved.head.height}</span>
      <span class="k">epoch</span><span class="v">${esc(resolved.view.inner_lite.epoch_id)}</span>
      <span class="k">signed stake</span><span class="v">${resolved.head.approvedStakePercent}% Â· ${resolved.head.signatureCount} validators</span>
    </div>
    ${renderChecks(resolved.checks)}
    ${resolved.notes.length ? `<div class="note">${resolved.notes.map(esc).join("<br />")}</div>` : ""}
  `;
  setBadge(resolved.trust, verified);
}

function renderError(message: string): void {
  el.output.hidden = false;
  el.output.innerHTML = `<p class="verdict" data-ok="false">VERIFICATION FAILED</p><p class="error">${esc(message)}</p>`;
  setBadge("failed", false);
}

function setBusy(value: boolean): void {
  busy = value;
  for (const button of [el.verify, el.example, el.head, el.repin, el.verifyState]) button.disabled = value;
  if (value) {
    el.output.hidden = false;
    el.output.innerHTML = `<p class="verdict" data-ok="true"><span class="spinner"></span> verifyingâ€¦</p>`;
  }
}

// ------------------------------------------------------------------ actions

const currentLie = (): Lie => el.lie.value as Lie;

function rpc(): NearRpc {
  liveEvents.length = 0;
  return new NearRpc({
    url: el.rpc.value.trim(),
    fetchImpl: createTamperedFetch(currentLie(), (message) => liveEvents.push(`attacker: ${message}`)),
  });
}

async function refreshCheckpointStatus(): Promise<void> {
  try {
    const resolved = await resolveHead({ rpcs: [rpc()], checkpoint, requireAnchor: false });
    const fresh = resolved.trust === "anchored";
    const age = checkpoint.capturedAt
      ? Math.round((Date.now() - Date.parse(checkpoint.capturedAt)) / 3_600_000)
      : null;
    el.checkpoint.dataset.state = fresh ? "fresh" : "stale";
    el.checkpoint.textContent = fresh
      ? `epoch ${checkpoint.epochId.slice(0, 8)}… · ${checkpoint.validators.length} producers pinned${
          age === null ? "" : ` · pinned ${age}h ago`
        } · fresh`
      : `epoch ${checkpoint.epochId.slice(0, 8)}… no longer covers the head (${
          resolved.view.inner_lite.epoch_id.slice(0, 8)
        }…) — press "re-pin current set" to restore anchored trust`;
  } catch (error) {
    el.checkpoint.dataset.state = "stale";
    el.checkpoint.textContent = `checkpoint unverified: ${error instanceof Error ? error.message : String(error)}`;
  }
}

const trustOptions = () => ({ checkpoint, requireAnchor: el.requireAnchor.checked });

async function runVerify(): Promise<void> {
  if (busy) return;
  const hash = el.tx.value.trim();
  const signer = el.signer.value.trim();
  if (!hash || !signer) {
    renderError("enter a transaction hash and its signer account id");
    return;
  }
  setBusy(true);
  try {
    if (currentLie() === "forge") {
      throw new Error(
        "a forged validator set has no real proofs to serve â€” use â€œCheck the head onlyâ€ to see this attack",
      );
    }
    const result = await verifyTransaction(hash, signer, { rpc: rpc(), ...trustOptions() });
    const outcome = result.value.outcome;
    const extra: Record<string, string> = {
      "executed at": `block ${result.value.height}`,
      status: Object.keys(outcome.status)[0] ?? "unknown",
      "block hash": result.value.blockHash,
    };
    const value = decodeSuccessValue(outcome);
    if (value !== null) extra["return value"] = value;
    renderResult(`transaction ${hash.slice(0, 16)}â€¦`, result, extra);
  } catch (error) {
    renderError(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

async function runState(): Promise<void> {
  if (busy) return;
  const accountId = el.account.value.trim();
  const key = el.storageKey.value;
  if (!accountId || !key) {
    renderError("enter a contract account id and a storage key");
    return;
  }
  setBusy(true);
  try {
    const result = await verifyContractState(accountId, new TextEncoder().encode(key), {
      rpc: rpc(),
      ...trustOptions(),
    });
    const notes = [...result.notes, ...liveEvents];
    el.output.hidden = false;
    el.output.innerHTML = `
      <h3>contract storage ${esc(accountId)} ["${esc(key)}"]</h3>
      <p class="verdict" data-ok="${result.verified}">${result.verified ? "VERIFIED" : "REJECTED"}</p>
      <div class="meta">
        <span class="k">trust</span><span class="v">${esc(TRUST_TEXT[result.trust])}</span>
        <span class="k">value</span><span class="v">${esc(result.value.valueText ?? "(absent)")}</span>
        <span class="k">state root</span><span class="v">${esc(result.value.stateRoot)}</span>
        <span class="k">shard</span><span class="v">${result.value.shard ?? "not located"} Â· block ${result.value.rootBlockHeight}</span>
      </div>
      ${renderChecks(result.checks)}
      ${notes.length ? `<div class="note">${notes.map(esc).join("<br />")}</div>` : ""}
    `;
    setBadge(result.trust, result.verified);
  } catch (error) {
    renderError(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

async function runHead(): Promise<void> {
  if (busy) return;
  setBusy(true);
  try {
    renderHeadOnly(await resolveHead({ rpcs: [rpc()], ...trustOptions() }));
  } catch (error) {
    renderError(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

async function loadExample(): Promise<void> {
  if (busy) return;
  setBusy(true);
  try {
    const client = rpc();
    const head = await client.finalBlock();
    for (let back = 6; back < 20; back++) {
      const tx = await client.findTransaction(Number(head.header.height) - back);
      if (tx) {
        el.tx.value = tx.hash;
        el.signer.value = tx.signer;
        el.output.hidden = true;
        return;
      }
    }
    throw new Error("could not find a recent transaction");
  } catch (error) {
    renderError(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

async function repin(): Promise<void> {
  if (busy) return;
  setBusy(true);
  try {
    // Trust-on-first-use: adopt the validator set this endpoint reports right now.
    const resolved = await resolveHead({ rpcs: [new NearRpc(el.rpc.value.trim())] });
    checkpoint = {
      network: "mainnet",
      epochId: resolved.view.inner_lite.epoch_id,
      nextEpochId: resolved.view.inner_lite.next_epoch_id,
      height: resolved.head.height,
      blockHash: b58encode(resolved.head.blockHash),
      validators: resolved.signers,
      validatorsHash: validatorsHash(resolved.signers),
      capturedAt: new Date().toISOString(),
      sourceRpc: el.rpc.value.trim(),
    };
    saveCheckpoint(checkpoint);
    await refreshCheckpointStatus();
    el.output.hidden = true;
  } catch (error) {
    renderError(error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

// ------------------------------------------------------------------ wiring

for (const lie of LIES) {
  const option = document.createElement("option");
  option.value = lie.value;
  option.textContent = lie.label;
  el.lie.append(option);
}

function syncBlurb(): void {
  const lie = LIES.find((l) => l.value === currentLie())!;
  el.lieBlurb.textContent = lie.blurb;
  el.lieBlurb.dataset.hostile = String(lie.value !== "none");
  el.verify.disabled = busy || lie.value === "forge";
  el.verifyState.disabled = busy || lie.value === "forge";
}

el.lie.addEventListener("change", () => {
  syncBlurb();
  liveEvents.length = 0;
  el.output.hidden = true;
  setBadge("idle");
});
el.requireAnchor.addEventListener("change", () => {
  liveEvents.length = 0;
  el.output.hidden = true;
  setBadge("idle");
});
el.verify.addEventListener("click", () => void runVerify());
el.head.addEventListener("click", () => void runHead());
el.example.addEventListener("click", () => void loadExample());
el.verifyState.addEventListener("click", () => void runState());
el.repin.addEventListener("click", () => void repin());
el.tx.addEventListener("keydown", (event) => {
  if ((event as KeyboardEvent).key === "Enter") void runVerify();
});

syncBlurb();
void refreshCheckpointStatus();

// A deployment can default to a verifying proxy instead of a raw RPC (see render.yaml).
const defaultRpc = (import.meta as any).env?.VITE_DEFAULT_RPC as string | undefined;
if (defaultRpc) el.rpc.value = defaultRpc;

