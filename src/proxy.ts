import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { makeCheckpoint, parseCheckpoint, type Checkpoint } from "./checkpoint.js";
import { b58encode } from "./base58.js";
import { authenticateBlockRoots, encodeInnerRest } from "./block-header.js";
import { sha256 } from "./borsh.js";
import { NearRpc } from "./rpc.js";
import { verifyContractState } from "./state.js";
import { resolveHead, type ResolvedHead } from "./trust.js";
import { verifyTransaction, verifyReceipt } from "./verifier.js";
import { b58decode } from "./base58.js";
import { equalBytes } from "./borsh.js";
import { bytesToBase64, bytesToHex } from "./bytes.js";

/**
 * `proven proxy` — a drop-in NEAR JSON-RPC endpoint that verifies what it forwards.
 *
 * Point any existing client at it (one URL change) and get:
 *   - `x-proven-verified: true|false|self` on every response
 *   - `x-proven-trust: anchored|quorum|rpc-asserted`
 *   - in `strict` mode, an error for methods that cannot be verified at all
 *
 * Nothing about the JSON-RPC payload changes, so near-api-js, plain `fetch`, and wallet code keep
 * working. The proxy never signs, never holds keys, and has no server-side state beyond counters.
 */
export interface ProxyOptions {
  /** Upstream RPC(s). Two or more enables quorum checking on heads. */
  upstream: string | string[];
  /** Pinned validator set; enables anchored verdicts. */
  checkpoint?: Checkpoint;
  /** Reject methods that cannot be verified instead of forwarding them. */
  strict?: boolean;
  /** Per-request upstream timeout. */
  timeoutMs?: number;
  /**
   * Called when the pin advances to the next epoch. A deployment can persist it, so a restart does
   * not fall back to a pin that expired while the process was down.
   */
  onRolled?: (checkpoint: Checkpoint) => void;
}

export type Verdict = "true" | "self" | "false" | "unverified" | "rejected";

export interface ProxyCounters {
  requests: number;
  verified: number;
  selfConsistent: number;
  failed: number;
  rejected: number;
}

const VERIFIABLE_METHODS = ["tx", "EXPERIMENTAL_tx_status", "query (view_state + include_proof)", "block"];

/** What kind of verification a request can support — classified per request, not per method name. */
type Verifiability = "proof" | "self" | "none";

function classify(method: string, params: any): Verifiability {
  if (method === "tx" || method === "EXPERIMENTAL_tx_status") return "proof";
  // Only an exact-key read can be checked: a prefix query returns a range of values that one trie
  // path does not commit to, and a specific `block_id` is a height we are not querying.
  if (
    method === "query" &&
    params?.request_type === "view_state" &&
    params?.include_proof &&
    params?.prefix_base64 &&
    params?.block_id === undefined
  ) {
    return "proof";
  }
  if (method === "block") return "self";
  return "none";
}

/** `tx` accepts positional params (`[hash, signer]`); normalise before reading fields. */
function txParams(params: any): { hash?: string; signer?: string } {
  if (Array.isArray(params)) return { hash: params[0], signer: params[1] };
  return { hash: params?.tx_hash, signer: params?.sender_account_id ?? params?.signer_account_id };
}

export interface ProvenProxy {
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  listen: (port: number, host?: string) => Promise<Server>;
  counters: ProxyCounters;
}

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, accept",
  "access-control-expose-headers":
    "x-proven-verified, x-proven-trust, x-proven-head, x-proven-method, x-proven-detail, x-proven-scope",
};

export function createProvenProxy(options: ProxyOptions): ProvenProxy {
  const upstreams = (Array.isArray(options.upstream) ? options.upstream : [options.upstream]).filter(Boolean);
  if (upstreams.length === 0) throw new Error("proxy needs at least one upstream RPC");
  const rpcs = upstreams.map((url) => new NearRpc({ url, timeoutMs: options.timeoutMs ?? 15_000 }));

  const counters: ProxyCounters = { requests: 0, verified: 0, selfConsistent: 0, failed: 0, rejected: 0 };
  let preferred = 0;

  const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...CORS, ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };

  const rpcError = (id: unknown, code: number, message: string, data?: unknown) => ({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message, ...(data === undefined ? {} : { data }) },
  });

  /** Compares the outcome the upstream reported with the one the proof committed to. */
  function outcomesMatch(reported: any, proven: any): boolean {
    if (!reported || !proven) return false;
    if (reported.executor_id !== proven.executor_id) return false;
    if (Number(reported.gas_burnt) !== Number(proven.gas_burnt)) return false;
    if (String(reported.tokens_burnt) !== String(proven.tokens_burnt)) return false;
    const reportedStatus = Object.keys(reported.status ?? {})[0];
    const provenStatus = Object.keys(proven.status ?? {})[0];
    if (reportedStatus !== provenStatus) return false;
    if (reportedStatus === "SuccessValue" && reported.status.SuccessValue !== proven.status.SuccessValue) return false;
    if (reportedStatus === "SuccessReceiptId" && reported.status.SuccessReceiptId !== proven.status.SuccessReceiptId) return false;
    const a = (reported.receipt_ids ?? []).join(",");
    const b = (proven.receipt_ids ?? []).join(",");
    return a === b;
  }

  /**
   * The head is what every proof is checked against, and resolving it costs several RPC round-trips.
   * It moves once a second, so holding it briefly is free in trust terms and turns a 6-call request
   * into a 1-call request. A proof built against a slightly older head still verifies — it only has
   * to be inside the head's block merkle tree.
   */
  const HEAD_TTL_MS = 5_000;
  let cachedHead: { at: number; resolved: ResolvedHead } | null = null;
  let headInFlight: Promise<ResolvedHead> | null = null;
  // The pin in force, and the one this process has already authenticated for the *next* epoch. The
  // next set is learned from the header the pinned validators signed, so adopting it later costs no
  // trust — but it must only be promoted once the head is actually inside its epoch, never before.
  let activeCheckpoint = options.checkpoint;
  let nextCheckpoint: Checkpoint | undefined;

  async function resolveWithPins(): Promise<ResolvedHead> {
    let resolved = await resolveHead({ rpcs, checkpoint: activeCheckpoint });

    // The epoch may have turned while this process was running: if the head is now in the epoch the
    // stashed set belongs to, verify with it instead of downgrading.
    if (nextCheckpoint && resolved.view.inner_lite.epoch_id === nextCheckpoint.epochId) {
      const promoted = await resolveHead({ rpcs, checkpoint: nextCheckpoint });
      if (promoted.trust === "anchored") {
        activeCheckpoint = nextCheckpoint;
        nextCheckpoint = undefined;
        resolved = promoted;
        console.log(
          `proven: pin advanced to epoch ${activeCheckpoint.epochId.slice(0, 8)}… (${activeCheckpoint.validators.length} producers) — anchored without re-pinning`,
        );
        options.onRolled?.(activeCheckpoint);
      }
    }

    if (resolved.nextPin) {
      nextCheckpoint = makeCheckpoint(resolved.view, resolved.nextPin.validators, {
        network: activeCheckpoint?.network ?? "mainnet",
        sourceRpc: activeCheckpoint?.sourceRpc,
      });
    }
    return resolved;
  }

  async function head(force = false): Promise<ResolvedHead> {
    if (!force && cachedHead && Date.now() - cachedHead.at < HEAD_TTL_MS) return cachedHead.resolved;
    if (!headInFlight) {
      headInFlight = resolveWithPins()
        .then((resolved) => {
          cachedHead = { at: Date.now(), resolved };
          return resolved;
        })
        .finally(() => {
          headInFlight = null;
        });
    }
    return headInFlight;
  }

  async function verify(
    method: string,
    params: any,
    result: any,
  ): Promise<{ verdict: Verdict; trust: string; detail: string; scope?: string }> {
    if (method === "tx" || method === "EXPERIMENTAL_tx_status") {
      const { hash, signer } = txParams(params);
      if (!hash || !signer) throw new Error("tx_status without a transaction hash and signer cannot be verified");
      const resolvedHead = await head();
      const run = (at: ResolvedHead) =>
        verifyTransaction(hash, signer, { rpcs, checkpoint: activeCheckpoint, resolvedHead: at });
      // A cached head can age out of the proof window; retry once against a fresh one.
      const proven = await run(resolvedHead).catch(async (error) => {
        if (!cachedHead) throw error;
        return run(await head(true));
      });
      const reported = result?.transaction_outcome?.outcome;
      if (!proven.verified || !outcomesMatch(reported, proven.value.outcome)) {
        return {
          verdict: "false",
          trust: proven.trust,
          detail: proven.verified
            ? "reported transaction outcome does not match the proven outcome"
            : `proof failed: ${proven.checks.find((c) => !c.ok)?.name ?? "unknown"}`,
          scope: "transaction_outcome",
        };
      }

      // The transaction outcome is only half the answer: `status` and `receipts_outcome` — where the
      // result of a contract call actually lives — come from the last receipt, so prove that too.
      const receipts: any[] = result?.receipts_outcome ?? [];
      let scope = "transaction_outcome";
      if (receipts.length > 0) {
        const last = receipts[receipts.length - 1];
        const receiptId = last?.id;
        const receiverId = last?.outcome?.executor_id;
        if (!receiptId || !receiverId) throw new Error("receipt without id/executor cannot be verified");
        const receiptProof = await verifyReceipt(receiptId, receiverId, {
          rpcs,
          checkpoint: activeCheckpoint,
          resolvedHead: await head(),
        });
        if (!receiptProof.verified || !outcomesMatch(last.outcome, receiptProof.value.outcome)) {
          return {
            verdict: "false",
            trust: receiptProof.trust,
            detail: receiptProof.verified
              ? `receipt ${receiptId.slice(0, 8)}… does not match its proof`
              : `receipt proof failed: ${receiptProof.checks.find((c) => !c.ok)?.name ?? "unknown"}`,
            scope: "transaction_outcome+receipt",
          };
        }
        scope = receipts.length === 1 ? "transaction_outcome+receipt" : `transaction_outcome+last_of_${receipts.length}_receipts`;
      }

      return {
        verdict: "true",
        trust: proven.trust,
        detail: `${proven.value.height} · ${proven.head.approvedStakePercent}% stake`,
        scope,
      };
    }

    if (method === "query" && params?.request_type === "view_state" && params?.include_proof) {
      const accountId = params.account_id;
      const key = params.prefix_base64 ? Uint8Array.from(Buffer.from(params.prefix_base64, "base64")) : new Uint8Array();
      const run = (resolvedHead: ResolvedHead) =>
        verifyContractState(accountId, key, { rpcs, checkpoint: activeCheckpoint, resolvedHead });
      const proven = await run(await head()).catch(async (error) => {
        if (!cachedHead) throw error;
        return run(await head(true));
      });
      const reported = (result?.values ?? [])[0];
      const matches = proven.value.value === null ? !reported : reported && bytesToBase64(proven.value.value) === reported.value;
      const ok = proven.verified && matches;
      return {
        verdict: ok ? "true" : "false",
        trust: proven.trust,
        detail: ok ? `state root ${proven.value.stateRoot.slice(0, 12)}…` : "returned values do not match the trie proof",
      };
    }

    if (method === "block") {
      // Self-consistency: recompute the header hash from its own contents. Catches any edited field,
      // though it cannot by itself prove the block belongs to the head.
      const header = result?.header;
      if (!header?.hash) throw new Error("block response has no header");
      let computed: Uint8Array;
      try {
        const innerLite = sha256(
          (() => {
            const l = header;
            return Buffer.concat([
              u64(l.height),
              b58decode(l.epoch_id),
              b58decode(l.next_epoch_id),
              b58decode(l.prev_state_root),
              b58decode(l.outcome_root),
              u64(l.timestamp_nanosec ?? l.timestamp),
              b58decode(l.next_bp_hash),
              b58decode(l.block_merkle_root),
            ]);
          })(),
        );
        const innerRest = sha256(encodeInnerRest(header));
        computed = sha256(sha256(innerLite, innerRest), b58decode(header.prev_hash));
      } catch (error) {
        // A protocol bump can add a header field this build does not encode. That is a limit of the
        // verifier, not evidence the answer is a lie: say "unverified" rather than refusing the call,
        // otherwise every `block` request breaks the day the layout changes.
        return {
          verdict: "unverified",
          trust: "none",
          detail: `header layout not supported by this build (${error instanceof Error ? error.message : String(error)})`,
        };
      }
      const ok = equalBytes(computed, b58decode(header.hash));
      return {
        verdict: ok ? "self" : "false",
        trust: "self-consistent",
        detail: ok ? `header hash recomputed (${bytesToHex(computed).slice(0, 12)}…)` : "header hash does not match its contents",
      };
    }

    return { verdict: "unverified", trust: "none", detail: "method has no proof primitive" };
  }

  async function handleRpc(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    let request: any;
    try {
      request = JSON.parse(body);
    } catch {
      send(res, 400, rpcError(null, -32700, "parse error"));
      return;
    }
    const method = request?.method;
    const params = request?.params;
    counters.requests++;

    // Forward first: the proxy is on the hot path, so the upstream's latency stays in front.
    // Extra upstreams are failover, and the last one that worked is tried first so a dead provider
    // costs one failed call, not one per request.
    let envelope: { result?: any; error?: any } | undefined;
    const errors: string[] = [];
    const order = [preferred, ...rpcs.map((_, i) => i)].filter((i, pos, all) => all.indexOf(i) === pos);
    for (const index of order) {
      try {
        envelope = await rpcs[index].callEnvelope(method, params ?? {});
        preferred = index;
        break;
      } catch (error) {
        errors.push(`${rpcs[index].url}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    if (!envelope) {
      send(res, 502, rpcError(request?.id, -32000, `upstream error: ${errors.join("; ")}`), { "x-proven-verified": "false" });
      return;
    }
    if (envelope.error) {
      // The node's own answer ("unknown block", "method not found") is forwarded verbatim: it is
      // data the caller needs, not a proxy failure.
      send(res, 200, { jsonrpc: "2.0", id: request?.id ?? null, error: envelope.error }, {
        "x-proven-verified": "false",
        "x-proven-trust": "none",
        "x-proven-method": String(method),
        "x-proven-detail": encodeURIComponent(String(envelope.error?.cause?.info?.error_message ?? envelope.error?.message ?? "upstream error")),
      });
      return;
    }
    const upstreamBody = envelope.result;

    const verifiability = classify(method, params);
    if (verifiability === "none") {
      if (options.strict) {
        counters.rejected++;
        send(
          res,
          200,
          rpcError(
            request?.id,
            -32001,
            `proven proxy (strict): "${method}" cannot be verified, so it is refused`,
            { verifiable: VERIFIABLE_METHODS },
          ),
          { "x-proven-verified": "rejected", "x-proven-method": String(method) },
        );
        return;
      }
      send(
        res,
        200,
        { jsonrpc: "2.0", id: request?.id ?? null, result: upstreamBody },
        { "x-proven-verified": "unverified", "x-proven-method": String(method) },
      );
      return;
    }

    let verdict: Verdict;
    let trust = "none";
    let detail = "";
    let scope = "";
    try {
      const verified = await verify(method, params, upstreamBody);
      verdict = verified.verdict;
      trust = verified.trust;
      detail = verified.detail;
      scope = verified.scope ?? "";
    } catch (error) {
      verdict = "false";
      detail = error instanceof Error ? error.message : String(error);
    }

    if (verdict === "true") counters.verified++;
    else if (verdict === "self") counters.selfConsistent++;
    else counters.failed++;

    const headers = {
      "x-proven-verified": verdict,
      "x-proven-trust": trust,
      "x-proven-method": String(method),
      "x-proven-detail": encodeURIComponent(detail),
      ...(scope ? { "x-proven-scope": scope } : {}),
    };

    if (verdict === "false") {
      // Never hand back data that failed verification: that is the whole point of the proxy.
      send(res, 200, rpcError(request?.id, -32002, `proven: verification failed — ${detail}`), headers);
      return;
    }
    send(res, 200, { jsonrpc: "2.0", id: request?.id ?? null, result: upstreamBody }, headers);
  }

  async function handleStatus(res: ServerResponse): Promise<void> {
    let headInfo: unknown = null;
    try {
      // Reuse the cached head: /status is polled by health checks, and resolving it per poll would
      // multiply the upstream traffic for no extra information.
      const resolved = await head();
      headInfo = {
        height: resolved.head.height,
        trust: resolved.trust,
        approvedStakePercent: resolved.head.approvedStakePercent,
        validators: resolved.signers.length,
        signerSource: resolved.signerSource,
      };
    } catch (error) {
      headInfo = { error: error instanceof Error ? error.message : String(error) };
    }
    send(res, 200, {
      service: "proven proxy",
      upstream: upstreams,
      active: upstreams[preferred],
      strict: Boolean(options.strict),
      checkpoint: activeCheckpoint
        ? {
            epochId: activeCheckpoint.epochId,
            validators: activeCheckpoint.validators.length,
            capturedAt: activeCheckpoint.capturedAt,
            rolled: activeCheckpoint.epochId !== options.checkpoint?.epochId,
          }
        : null,
      verifiable: VERIFIABLE_METHODS,
      head: headInfo,
      counters,
    });
  }

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, CORS);
      res.end();
      return;
    }
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/status")) {
      void handleStatus(res);
      return;
    }
    if (req.method === "GET" && url.pathname === "/health") {
      send(res, 200, { ok: true, counters });
      return;
    }
    if (req.method === "POST") {
      void handleRpc(req, res).catch((error) => {
        send(res, 500, rpcError(null, -32603, `internal error: ${error instanceof Error ? error.message : error}`));
      });
      return;
    }
    send(res, 404, { error: "POST JSON-RPC to /, GET / for status" });
  };

  return {
    handler,
    counters,
    listen: (port, host = "0.0.0.0") =>
      new Promise((resolve) => {
        const server = createServer(handler);
        server.listen(port, host, () => resolve(server));
      }),
  };
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2_000_000) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function u64(n: number | string): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

/** Reads a checkpoint file when configured, ignoring a missing one but never a broken one silently. */
export function loadCheckpoint(path: string | undefined): Checkpoint | undefined {
  if (!path) return undefined;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  try {
    return parseCheckpoint(raw);
  } catch (error) {
    // Running without a pin is a real downgrade, so say so rather than serving weaker verdicts quietly.
    console.warn(
      `proven: ignoring ${path}: ${error instanceof Error ? error.message : String(error)} — verdicts will not be "anchored" until it is fixed`,
    );
    return undefined;
  }
}

export { b58encode };
