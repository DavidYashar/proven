import {
  NearRpc,
  verifyContractState,
  decodeSuccessValue,
  makeCheckpoint,
  parseCheckpoint,
  resolveHead,
  verifyTransaction,
  type Check,
  type Checkpoint,
  type ProvenResult,
  type TrustLevel,
} from "../../dist/index.js";
import checkpointJson from "../../checkpoints/mainnet.json";
import { createTamperedFetch, LIES, type Lie } from "./tamper.js";
import { probeProvider, PROVIDERS, type ProbeResult } from "./providers.js";

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
  hostedUrl: $<HTMLElement>("hosted-url"),
  hostedWarn: $<HTMLElement>("hosted-warn"),
  copyHosted: $<HTMLButtonElement>("copy-hosted"),
  runCmd: $<HTMLElement>("run-cmd"),
  upstreamNote: $<HTMLElement>("upstream-note"),
  upstreamWarn: $<HTMLElement>("upstream-warn"),
  copyCommand: $<HTMLButtonElement>("copy-command"),
  copyLocal: $<HTMLButtonElement>("copy-local"),
  localUrl: $<HTMLElement>("local-url"),
  provider: $<HTMLSelectElement>("provider"),
  providerHint: $<HTMLElement>("provider-hint"),
  providerResults: $<HTMLElement>("provider-results"),
  checkEndpoint: $<HTMLButtonElement>("check-endpoint"),
};

/**
 * The endpoint an app should point at. It is a *verifying* endpoint, so it must be either our
 * deployment or a proxy the user runs — never the raw provider the page happens to be checking.
 */
const HOSTED_URL = ((import.meta as any).env?.VITE_PROXY_URL as string | undefined) ?? "https://proven-proxy.onrender.com";
const LOCAL_URL = "http://localhost:8080";

/**
 * What the last check said about the provider currently in the field. `bad` means it could not serve a
 * light client proof — the honest advice is then "do not configure your proxy with this", so the UI
 * says so instead of offering a copy button that would mislead.
 */
let upstreamCheck: "unknown" | "ok" | "bad" = "unknown";

const STORAGE_KEY = "proven.checkpoint.v1";

/**
 * The pin this page verifies against. `firstUse` marks a pin that was adopted from one endpoint on
 * trust rather than walked from a pin this page already trusted; it rides along when the pin is later
 * walked forward (`bridgeCheckpoint` keeps unknown fields), so the weaker origin is never forgotten.
 */
type WebCheckpoint = Checkpoint & { firstUse?: { rpc: string; at: string } };
type Head = Awaited<ReturnType<typeof resolveHead>>;

const shippedCheckpoint = (): WebCheckpoint => parseCheckpoint(JSON.stringify(checkpointJson));

function loadCheckpoint(): WebCheckpoint {
  const shipped = shippedCheckpoint();
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    // A stored pin older than the one this build ships (say, from before a redeploy) is never better:
    // the shipped pin is the trust root and is nearer the head.
    if (stored) {
      const pin: WebCheckpoint = parseCheckpoint(stored);
      if (pin.height >= shipped.height) return pin;
    }
  } catch {
    /* ignore corrupt storage and fall back to the shipped pin */
  }
  return shipped;
}

function saveCheckpoint(value: WebCheckpoint): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    /* private mode: the pin simply will not persist */
  }
}

let checkpoint: WebCheckpoint = loadCheckpoint();
let busy = false;
const liveEvents: string[] = [];

// ------------------------------------------------------------------ rendering

const esc = (s: unknown): string =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const TRUST_TEXT: Record<TrustLevel, string> = {
  anchored: "anchored · pinned validator set",
  quorum: "quorum · independent RPCs agree",
  "rpc-asserted": "rpc-asserted · self-consistent only",
};

/** Anchored to a pin taken on first use is only as good as the one endpoint it came from: say so. */
const firstUseAnchor = (trust: TrustLevel | "idle" | "failed"): boolean =>
  trust === "anchored" && Boolean(checkpoint.firstUse);

const trustText = (trust: TrustLevel): string =>
  firstUseAnchor(trust) ? "anchored · pinned on first use from one RPC" : TRUST_TEXT[trust];

function setBadge(trust: TrustLevel | "idle" | "failed", ok = true): void {
  // A rejected result must not advertise the trust level it was aiming for.
  const shown = ok && trust !== "failed" ? trust : "failed";
  el.badge.dataset.trust = firstUseAnchor(shown) ? "anchored-first-use" : shown;
  el.badge.textContent = shown === "idle" || shown === "failed" ? shown : trustText(shown);
}

function renderChecks(checks: Check[]): string {
  return `<ul class="checks">${checks
    .map(
      (c) => `<li data-ok="${c.ok}">
        <span class="mark">${c.ok ? "✓" : "✗"}</span>
        <span><span class="name">${esc(c.name)}</span>${
          c.detail ? `<br /><span class="detail">${esc(c.detail)}</span>` : ""
        }</span>
      </li>`,
    )
    .join("")}</ul>`;
}

/** Appended wherever a transport verdict is shown, so the words and the badge agree. */
const TRANSPORT_NOTE =
  "Nothing was proven either way: the endpoint did not answer the checks it could not serve. That is a network problem, not a verdict on the chain.";

/**
 * A failed check whose reason is the network is not evidence of a lie. When *every* failure is a
 * transport failure, the honest verdict is "nothing was checked" — otherwise a provider that simply
 * sends no CORS headers gets accused of forging the chain it never got to answer about.
 */
const onlyTransportFailed = (checks: Check[]): boolean => {
  const failed = checks.filter((c) => !c.ok);
  return failed.length > 0 && failed.every((c) => looksLikeTransport(c.detail ?? ""));
};

const verdictOf = (verified: boolean, checks: Check[]): { text: string; kind: string } =>
  verified
    ? { text: "VERIFIED", kind: "verified" }
    : onlyTransportFailed(checks)
      ? { text: "NOT VERIFIED — the endpoint did not answer", kind: "transport" }
      : { text: "REJECTED", kind: "verdict" };

function renderResult<T>(title: string, result: ProvenResult<T>, extra: Record<string, string>): void {
  const verdict = verdictOf(result.verified, result.checks);
  const notes = [...result.notes, ...liveEvents];
  if (verdict.kind === "transport") notes.push(TRANSPORT_NOTE);
  el.output.hidden = false;
  el.output.innerHTML = `
    <h3>${esc(title)}</h3>
    <p class="verdict" data-ok="${result.verified}" data-kind="${verdict.kind}">${verdict.text}</p>
    <div class="meta">
      <span class="k">trust</span><span class="v">${esc(trustText(result.trust))}</span>
      <span class="k">light client head</span><span class="v">${result.head.height} · ${result.head.approvedStakePercent}% of staked NEAR signed</span>
      ${Object.entries(extra)
        .map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`)
        .join("")}
    </div>
    ${result.checks.length ? renderChecks(result.checks) : ""}
    ${notes.length ? `<div class="note">${notes.map(esc).join("<br />")}</div>` : ""}
  `;
  setBadge(result.trust, result.verified);
}

function renderHeadOnly(resolved: Head): void {
  const verified = resolved.checks.every((c) => c.ok);
  const verdict = verdictOf(verified, resolved.checks);
  const notes = [...resolved.notes, ...(verdict.kind === "transport" ? [TRANSPORT_NOTE] : [])];
  el.output.hidden = false;
  el.output.innerHTML = `
    <h3>light client head</h3>
    <p class="verdict" data-ok="${verified}" data-kind="${verdict.kind}">${verdict.text}</p>
    <div class="meta">
      <span class="k">trust</span><span class="v">${esc(trustText(resolved.trust))}</span>
      <span class="k">height</span><span class="v">${resolved.head.height}</span>
      <span class="k">epoch</span><span class="v">${esc(resolved.view.inner_lite.epoch_id)}</span>
      <span class="k">signed stake</span><span class="v">${resolved.head.approvedStakePercent}% · ${resolved.head.signatureCount} validators</span>
    </div>
    ${renderChecks(resolved.checks)}
    ${notes.length ? `<div class="note">${notes.map(esc).join("<br />")}</div>` : ""}
  `;
  setBadge(resolved.trust, verified);
}

/**
 * A transport problem is not a verdict. When the endpoint is unreachable or throttling, saying
 * "VERIFICATION FAILED" would accuse the chain of lying when nothing was checked at all.
 */
const looksLikeTransport = (message: string): boolean =>
  /did not serve|did not answer|not answered|failed to fetch|no rpc could|rate limit|too many requests|429|timed out|abort|network/i.test(
    message,
  );

function renderError(message: string): void {
  el.output.hidden = false;
  const transport = looksLikeTransport(message);
  el.output.innerHTML = `<p class="verdict" data-ok="false" data-kind="${transport ? "transport" : "verdict"}">${
    transport ? "NOT VERIFIED — the endpoint did not answer" : "VERIFICATION FAILED"
  }</p><p class="error">${esc(message)}</p>${
    transport
      ? `<p class="note">Nothing was proven either way: the endpoint was unreachable or throttling. A public RPC rate-limits under repeated use, so the answer is usually a different endpoint — pick one above, or paste a URL that works.</p>`
      : ""
  }`;
  setBadge("failed", false);
  if (transport) {
    el.providerHint.textContent = `${labelFor(el.rpc.value.trim())} could not prove anything — pick another provider above, or paste a URL that can`;
  }
}

/**
 * An inline yes/no instead of a modal: the reason stays on the page next to the buttons, so the user can
 * still read it while deciding, and nothing blocks the rest of the app.
 */
function confirmInline(html: string, yesLabel: string, noLabel: string): Promise<boolean> {
  return new Promise((resolve) => {
    el.output.hidden = false;
    el.output.innerHTML = `<div class="confirm">${html}<div class="confirm-actions">
      <button class="ghost" type="button" data-confirm="yes">${esc(yesLabel)}</button>
      <button class="ghost" type="button" data-confirm="no">${esc(noLabel)}</button>
    </div></div>`;
    const onClick = (event: Event): void => {
      const choice = (event.target as HTMLElement | null)?.dataset?.confirm;
      if (!choice) return;
      el.output.removeEventListener("click", onClick);
      el.output.innerHTML = "";
      resolve(choice === "yes");
    };
    el.output.addEventListener("click", onClick);
  });
}

/** When the endpoint last answered anything at all — the measure the silence limit watches. */
let lastResponseAt = Date.now();
let busySince = 0;
let busyTicker: ReturnType<typeof setInterval> | undefined;

const hostOf = (url: string): string => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

/**
 * A dead endpoint does not fail fast: the retry and the light-client walk are each a 10 s stall, and a
 * head check piles several of them up (measured: 36 s of a spinner that says nothing). This turns
 * silence into a verdict — if nothing has come back for `SILENCE_MS`, stop waiting and say so. The
 * clock resets on every answer, so a slow-but-working endpoint is never declared dead.
 */
const SILENCE_MS = 20_000;

function withSilenceLimit<T>(work: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const watch = setInterval(() => {
      if (Date.now() - lastResponseAt > SILENCE_MS) {
        clearInterval(watch);
        reject(new Error(`the endpoint has not answered for ${Math.round(SILENCE_MS / 1000)}s`));
      }
    }, 500);
    const settle = (): void => clearInterval(watch);
    work.then(
      (value) => {
        settle();
        resolve(value);
      },
      (error) => {
        settle();
        reject(error);
      },
    );
  });
}

function setBusy(value: boolean): void {
  busy = value;
  for (const button of [el.verify, el.example, el.head, el.repin, el.verifyState]) button.disabled = value;
  if (busyTicker !== undefined) {
    clearInterval(busyTicker);
    busyTicker = undefined;
  }
  if (!value) return;

  lastResponseAt = Date.now();
  busySince = Date.now();
  el.output.hidden = false;
  // Never a spinner with no information in it: say how long, and what is being waited on.
  const paint = (): void => {
    const seconds = Math.round((Date.now() - busySince) / 1000);
    el.output.innerHTML = `<p class="verdict" data-ok="true"><span class="spinner"></span> verifying… ${seconds}s${
      seconds >= 3 ? `<span class="waiting">waiting for ${esc(hostOf(el.rpc.value.trim()))}</span>` : ""
    }</p>`;
  };
  paint();
  busyTicker = setInterval(paint, 1000);
}

/**
 * Runs one user action under the silence limit. Every action goes through here, so a dead endpoint can
 * only ever end in a verdict — never in a spinner that outlives the user's patience. The returned
 * promise settles with the action, so callers that await it (a provider switch) see the verdict.
 */
function runAction(work: () => Promise<void>, options: { markUpstreamBad?: boolean } = {}): Promise<void> {
  if (busy) return Promise.resolve();
  setBusy(true);
  return withSilenceLimit(work())
    .catch((error) => {
      renderError(error instanceof Error ? error.message : String(error));
      if (options.markUpstreamBad !== false) markUpstream("bad");
    })
    .finally(() => setBusy(false));
}

// ------------------------------------------------------------------ actions

const currentLie = (): Lie => el.lie.value as Lie;

/**
 * Stamps every *answer* onto the clock the silence limit reads. A rejected fetch is not an answer — a
 * dead endpoint rejects every 10 s, and counting those as progress is what let a head check spin for
 * 42 s. Successes only: any real response (even a JSON-RPC error) proves the endpoint is alive.
 */
function measuredFetch(inner: typeof fetch): typeof fetch {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const pending = inner(input as any, init);
    pending.then(
      () => {
        lastResponseAt = Date.now();
      },
      () => {},
    );
    return pending;
  };
}

function rpc(): NearRpc {
  liveEvents.length = 0;
  // Every request goes through this wrapper, so "has it answered anything at all" is measurable and the
  // silence limit is about the endpoint, not about how much work is queued behind it.
  return new NearRpc({
    url: el.rpc.value.trim(),
    fetchImpl: measuredFetch(createTamperedFetch(currentLie(), (message) => liveEvents.push(`attacker: ${message}`))),
  });
}

/** The endpoint as it is, never through the demo's tampering — used for pin upkeep. */
function plainRpc(url: string): NearRpc {
  return new NearRpc({ url, fetchImpl: measuredFetch(fetch) });
}

async function refreshCheckpointStatus(): Promise<void> {
  try {
    // Pin upkeep goes to the endpoint as it is, never through the demo's tampering: a lie chosen for
    // the next verification must not be what decides whether the pin is kept fresh.
    const resolved = await resolveHead({ rpcs: [plainRpc(el.rpc.value.trim())], checkpoint, requireAnchor: false });
    adoptWalkedPin(resolved);
    showCheckpointStatus(resolved);
  } catch (error) {
    el.checkpoint.dataset.state = "stale";
    el.checkpoint.textContent = `checkpoint unverified: ${error instanceof Error ? error.message : String(error)}`;
  }
}

function showCheckpointStatus(resolved: Head): void {
  const fresh = resolved.trust === "anchored";
  const age = checkpoint.capturedAt
    ? Math.round((Date.now() - Date.parse(checkpoint.capturedAt)) / 3_600_000)
    : null;
  el.checkpoint.dataset.state = !fresh ? "stale" : checkpoint.firstUse ? "first-use" : "fresh";
  el.checkpoint.textContent = !fresh
    ? `epoch ${checkpoint.epochId.slice(0, 8)}… no longer covers the head (${
        resolved.view.inner_lite.epoch_id.slice(0, 8)
      }…) — press "re-pin current set" to restore anchored trust`
    : `epoch ${checkpoint.epochId.slice(0, 8)}… · ${checkpoint.validators.length} producers pinned${
        checkpoint.firstUse ? ` on first use from ${checkpoint.firstUse.rpc}` : ""
      }${age === null ? "" : ` · ${age}h ago`} · fresh`;
}

/**
 * Keeps a pin the library walked forward. Every hop was signature-checked by the set before it, so it
 * is exactly as trustworthy as the pin it started from — and keeping it means the next verification
 * does not pay for the same walk again.
 */
function adoptWalkedPin(resolved: Head): void {
  if (!resolved.bridgedPin) return;
  checkpoint = resolved.bridgedPin;
  saveCheckpoint(checkpoint);
  showCheckpointStatus(resolved);
}

const trustOptions = () => ({ checkpoint, requireAnchor: el.requireAnchor.checked });

/** Resolves the head once per action (the verifiers reuse it) and keeps any pin it walked forward. */
async function headFor(client: NearRpc): Promise<Head> {
  const resolved = await resolveHead({ rpcs: [client], ...trustOptions() });
  adoptWalkedPin(resolved);
  return resolved;
}

async function runVerify(): Promise<void> {
  if (busy) return;
  const hash = el.tx.value.trim();
  const signer = el.signer.value.trim();
  if (!hash || !signer) {
    renderError("enter a transaction hash and its signer account id");
    return;
  }
  return runAction(async () => {
    if (currentLie() === "forge") {
      throw new Error(
        "a forged validator set has no real proofs to serve — use “Check the head only” to see this attack",
      );
    }
    const client = rpc();
    const resolvedHead = await headFor(client);
    const result = await verifyTransaction(hash, signer, { rpc: client, ...trustOptions(), resolvedHead });
    const outcome = result.value.outcome;
    const extra: Record<string, string> = {
      "executed at": `block ${result.value.height}`,
      status: Object.keys(outcome.status)[0] ?? "unknown",
      "block hash": result.value.blockHash,
    };
    const value = decodeSuccessValue(outcome);
    if (value !== null) extra["return value"] = value;
    renderResult(`transaction ${hash.slice(0, 16)}…`, result, extra);
    markUpstream(result.verified ? "ok" : "bad");
  });
}

async function runState(): Promise<void> {
  if (busy) return;
  const accountId = el.account.value.trim();
  const key = el.storageKey.value;
  if (!accountId || !key) {
    renderError("enter a contract account id and a storage key");
    return;
  }
  return runAction(async () => {
    const client = rpc();
    const resolvedHead = await headFor(client);
    const result = await verifyContractState(accountId, new TextEncoder().encode(key), {
      rpc: client,
      ...trustOptions(),
      resolvedHead,
    });
    const notes = [...result.notes, ...liveEvents];
    el.output.hidden = false;
    el.output.innerHTML = `
      <h3>contract storage ${esc(accountId)} ["${esc(key)}"]</h3>
      <p class="verdict" data-ok="${result.verified}">${result.verified ? "VERIFIED" : "REJECTED"}</p>
      <div class="meta">
        <span class="k">trust</span><span class="v">${esc(trustText(result.trust))}</span>
        <span class="k">value</span><span class="v">${esc(result.value.valueText ?? "(absent)")}</span>
        <span class="k">state root</span><span class="v">${esc(result.value.stateRoot)}</span>
        <span class="k">shard</span><span class="v">${result.value.shard ?? "not located"} · block ${result.value.rootBlockHeight}</span>
      </div>
      ${renderChecks(result.checks)}
      ${notes.length ? `<div class="note">${notes.map(esc).join("<br />")}</div>` : ""}
    `;
    setBadge(result.trust, result.verified);
    markUpstream(result.verified ? "ok" : "bad");
  });
}

async function runHead(): Promise<void> {
  if (busy) return;
  return runAction(async () => {
    const resolved = await headFor(rpc());
    const verified = resolved.checks.every((c) => c.ok);
    renderHeadOnly(resolved);
    markUpstream(verified ? "ok" : "bad");
  });
}

async function loadExample(): Promise<void> {
  if (busy) return;
  return runAction(async () => {
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
  }, { markUpstreamBad: false });
}

async function repin(): Promise<void> {
  if (busy) return;
  return runAction(async () => {
    const rpcUrl = el.rpc.value.trim();
    // Pin upkeep never goes through the demo's tampering.
    const client = plainRpc(rpcUrl);

    // First, reach the current epoch from a pin this page already trusts. Each hop is signed by the set
    // the previous one committed to, so the result is exactly as strong as the starting pin — no
    // endpoint is taken at its word. The shipped pin is the root; a stored pin that was itself walked
    // from it is closer to the head, so it is tried first.
    const candidates = [checkpoint, shippedCheckpoint()].filter(
      (pin, index, all) => !pin.firstUse && all.findIndex((other) => other.blockHash === pin.blockHash) === index,
    );
    const reasons: string[] = [];
    for (const candidate of candidates) {
      try {
        const resolved = await resolveHead({ rpcs: [client], checkpoint: candidate, requireAnchor: true });
        if (resolved.trust === "anchored" && resolved.checks.every((c) => c.ok)) {
          checkpoint = resolved.bridgedPin ?? candidate;
          saveCheckpoint(checkpoint);
          showCheckpointStatus(resolved);
          el.output.hidden = true;
          return;
        }
        reasons.push(
          resolved.notes[resolved.notes.length - 1] ?? resolved.checks.find((c) => !c.ok)?.detail ?? "not anchored",
        );
      } catch (error) {
        reasons.push(error instanceof Error ? error.message : String(error));
      }
    }

    // Only when no trusted pin can be walked forward is trust-on-first-use on the table, and then only
    // with the user's say-so: it takes the producer set from this one endpoint on its word.
    const accepted = await confirmInline(
      `<p class="note"><strong>No trusted pin could be walked forward to the current epoch</strong> through ${esc(rpcUrl)}${
        reasons.length ? ` — ${esc(reasons.join("; "))}` : ""
      }.</p>
       <p class="note">An archival endpoint (for example <code>https://archival-rpc.mainnet.fastnear.com</code>) keeps the history that walk needs, so trying it first is usually better.</p>
       <p class="note">Otherwise the page can pin the validator set this endpoint reports right now. That is trust-on-first-use: if this endpoint is lying, everything verified afterwards is anchored to its lie, and the badge will say so.</p>`,
      "pin what this endpoint reports",
      "not now",
    );
    if (!accepted) {
      await refreshCheckpointStatus();
      el.output.hidden = true;
      return;
    }
    const resolved = await resolveHead({ rpcs: [client] });
    if (!resolved.checks.every((c) => c.ok)) {
      throw new Error("this endpoint's own head does not verify against the set it reports; nothing was pinned");
    }
    checkpoint = {
      ...makeCheckpoint(resolved.view, resolved.signers, { network: "mainnet", sourceRpc: rpcUrl }),
      firstUse: { rpc: rpcUrl, at: new Date().toISOString() },
    };
    saveCheckpoint(checkpoint);
    await refreshCheckpointStatus();
    el.output.hidden = true;
  }, { markUpstreamBad: false });
}

// ------------------------------------------------------------------ "use it" card

function upstreamValue(): string {
  return el.rpc.value.trim() || "https://free.rpc.fastnear.com";
}

/**
 * Records what the last check said about the provider in the field, so the "copy this into your app"
 * advice can be withheld when that provider just failed to prove anything.
 */
function markUpstream(state: "unknown" | "ok" | "bad"): void {
  upstreamCheck = state;
  updateUseCard();
}

function updateUseCard(): void {
  const upstream = upstreamValue();
  const normalize = (url: string) => url.replace(/\/+$/, "");
  // A verifying endpoint is already the answer: pointing a proxy at a proxy would only add a hop.
  const alreadyVerifying = [HOSTED_URL, LOCAL_URL].some((url) => normalize(url) === normalize(upstream));

  el.hostedUrl.textContent = HOSTED_URL;

  if (alreadyVerifying) {
    el.localUrl.textContent = upstream;
    el.runCmd.textContent =
      "# nothing to run: this endpoint already verifies\n" + `# paste it into your app as it is\nNEAR_RPC_URL=${upstream}`;
    el.upstreamNote.textContent = "that endpoint already verifies — use it as it is";
    el.upstreamWarn.hidden = true;
    el.copyCommand.disabled = true;
    el.copyLocal.disabled = false;
    return;
  }

  el.localUrl.textContent = LOCAL_URL;
  el.runCmd.textContent = `UPSTREAM_RPC=${upstream} node dist/proxy-cli.js\n# then: NEAR_RPC_URL=${LOCAL_URL}`;
  el.upstreamNote.textContent =
    upstreamCheck === "ok"
      ? "that provider verified a moment ago"
      : upstreamCheck === "bad"
        ? "that provider did not verify"
        : "using the endpoint checked above";
  el.upstreamWarn.hidden = upstreamCheck !== "bad";
  el.copyCommand.disabled = upstreamCheck === "bad";
  el.copyLocal.disabled = upstreamCheck === "bad";
}

/** Copy, with a visible confirmation and a fallback for browsers without clipboard permission. */
async function copyText(text: string, button: HTMLButtonElement): Promise<void> {
  const label = button.textContent ?? "Copy";
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard API needs a secure context; selecting the text still lets the user press Ctrl+C.
    const range = document.createRange();
    const pre = document.createElement("pre");
    pre.textContent = text;
    document.body.append(pre);
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    pre.remove();
  }
  button.textContent = "Copied";
  button.dataset.copied = "true";
  setTimeout(() => {
    button.textContent = label;
    delete button.dataset.copied;
  }, 1500);
}

/**
 * Is the hosted endpoint awake? A free instance sleeps when idle, so the card must not promise a URL
 * that is not answering right now.
 */
async function probeHosted(): Promise<void> {
  try {
    const response = await fetch(`${HOSTED_URL.replace(/\/+$/, "")}/status`, {
      signal: AbortSignal.timeout(9_000),
    });
    const body: any = await response.json();
    el.hostedWarn.hidden = Boolean(body?.service);
  } catch {
    el.hostedWarn.hidden = false;
  }
}

// ------------------------------------------------------------------ provider picker

let probing = false;

/** The pinned epoch-start block is the only honest thing to ask a stranger for — see probeProvider. */
const pinnedAnchor = (): string | undefined => checkpoint?.blockHash;

function fillProviderSelect(): void {
  for (const provider of PROVIDERS) {
    const option = document.createElement("option");
    option.value = provider.url ?? `key:${provider.id}`;
    option.textContent = `${provider.label} — ${provider.note}`;
    option.disabled = !provider.url;
    el.provider.append(option);
  }
  const custom = document.createElement("option");
  custom.value = "custom";
  custom.textContent = "Custom endpoint…";
  el.provider.append(custom);
  syncProviderSelect();
}

function syncProviderSelect(): void {
  const current = el.rpc.value.trim().replace(/\/+$/, "");
  const match = PROVIDERS.find((p) => p.url && p.url.replace(/\/+$/, "") === current);
  el.provider.value = match?.url ?? "custom";
}

const STATUS_MARK: Record<string, string> = { ok: "✓", "no-proofs": "✗", unreachable: "⛔", "http-error": "⛔" };

const normalizeUrl = (url: string): string => url.replace(/\/+$/, "");

const labelFor = (url: string): string =>
  PROVIDERS.find((p) => p.url && normalizeUrl(p.url) === normalizeUrl(url))?.label ?? url;

/** What the endpoint in the field answered — one row, about that endpoint only. */
function renderEndpointStatus(result: ProbeResult | null): void {
  if (!result) {
    el.providerResults.hidden = true;
    el.providerResults.innerHTML = "";
    return;
  }
  el.providerResults.hidden = false;
  el.providerResults.innerHTML = `<div class="provider-row" data-status="${result.status}">
    <span class="provider-mark">${STATUS_MARK[result.status] ?? "?"}</span>
    <span class="provider-name">${esc(result.label)}<br /><span class="provider-detail">${esc(result.detail)} · ${result.ms} ms</span></span>
  </div>`;
}

/**
 * Asks the one endpoint in the field whether it can prove anything. Only that endpoint: sweeping the
 * rest of the list would load-test public infrastructure to answer a question nobody asked.
 */
async function probeCurrentEndpoint(): Promise<ProbeResult | null> {
  const url = el.rpc.value.trim();
  if (!url || probing) return null;
  probing = true;
  el.checkEndpoint.disabled = true;
  el.providerHint.textContent = `asking ${labelFor(url)}…`;
  try {
    const result = await probeProvider(url, labelFor(url), pinnedAnchor());
    renderEndpointStatus(result);
    el.providerHint.textContent =
      result.status === "ok"
        ? `${result.label} serves light client blocks — "Check the head only" verifies it end to end`
        : `${result.label} cannot prove anything — pick another provider above, or paste a URL that can`;
    return result;
  } finally {
    probing = false;
    el.checkEndpoint.disabled = false;
  }
}

/** Switches the page to a provider the user picked, then proves it works so the answer is visible. */
async function useProvider(url: string): Promise<void> {
  el.rpc.value = url;
  syncProviderSelect();
  markUpstream("unknown");
  renderEndpointStatus(null);
  el.providerHint.textContent = `checking ${labelFor(url)}…`;
  await runHead();
  if (upstreamCheck === "ok") {
    el.providerHint.textContent = `${labelFor(url)} works — verified against validators`;
    // The checkpoint row was last written for the previous endpoint; it must not go on blaming it.
    void refreshCheckpointStatus();
  } else {
    el.providerHint.textContent = `${labelFor(url)} cannot prove anything — pick another provider above, or paste a URL that can`;
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

// The "use it" card follows whatever provider is in the field.
el.rpc.addEventListener("input", () => {
  upstreamCheck = "unknown";
  syncProviderSelect();
  updateUseCard();
});
// A pasted or edited endpoint is checked when the user is done with it — that endpoint only.
el.rpc.addEventListener("change", () => void probeCurrentEndpoint());
el.provider.addEventListener("change", () => {
  if (el.provider.value === "custom") {
    el.rpc.focus();
    el.rpc.select();
    return;
  }
  void useProvider(el.provider.value);
});
el.checkEndpoint.addEventListener("click", () => void probeCurrentEndpoint());
el.copyHosted.addEventListener("click", () => void copyText(HOSTED_URL, el.copyHosted));
el.copyLocal.addEventListener("click", () => void copyText(LOCAL_URL, el.copyLocal));
el.copyCommand.addEventListener("click", () => void copyText(el.runCmd.textContent ?? "", el.copyCommand));

syncBlurb();
updateUseCard();
void probeHosted();

// A deployment can default to a verifying proxy instead of a raw RPC (see render.yaml). This must be
// applied before the first status check, or that check probes the endpoint baked into the HTML.
const defaultRpc = (import.meta as any).env?.VITE_DEFAULT_RPC as string | undefined;
if (defaultRpc) {
  el.rpc.value = defaultRpc;
  updateUseCard();
}

fillProviderSelect();

void refreshCheckpointStatus();

