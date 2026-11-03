// Known NEAR RPC providers, and a live probe of whether this browser can actually verify against one.
//
// The list mirrors docs.near.org/api/rpc/providers (mainnet, public HTTP endpoints). It is a starting
// point, not an allow-list: any node answers the two methods a verifier needs, so a custom URL always
// works if that endpoint does. What decides usability here is empirical, not documented:
//
//   - reachable        the browser could POST to it at all (a gateway with no CORS looks "down")
//   - servesProofs     it answers `next_light_client_block` for a pinned epoch-start block
//   - needsKey         the public path rejects anonymous calls
//
// The probe asks one endpoint — the one the user picked — and reports what happened. It deliberately
// does not sweep the list: these are public endpoints, and finding an alternative is the user's choice,
// not a reason to load-test somebody else's infrastructure.

export interface KnownProvider {
  id: string;
  label: string;
  /** `null` when the provider has no public endpoint (key-gated or node-only). */
  url: string | null;
  /** Short honest note shown next to the name. */
  note: string;
  archival?: boolean;
  keyed?: boolean;
}

export const PROVIDERS: KnownProvider[] = [
  {
    id: "fastnear",
    label: "FastNear",
    url: "https://free.rpc.fastnear.com",
    note: "free tier, not archival",
  },
  {
    id: "near-archival",
    label: "NEAR (archival)",
    url: "https://archival-rpc.mainnet.near.org",
    note: "archival, severely rate limited",
    archival: true,
  },
  {
    id: "near",
    label: "NEAR",
    url: "https://rpc.mainnet.near.org",
    note: "archival, deprecated",
    archival: true,
  },
  { id: "intear", label: "Intear RPC", url: "https://rpc.intea.rs", note: "free, no published limit" },
  { id: "shitzu", label: "Shitzu", url: "https://rpc.shitzuapes.xyz", note: "free, no published limit" },
  { id: "1rpc", label: "1RPC", url: "https://1rpc.io/near", note: "200 req/day" },
  { id: "drpc", label: "dRPC", url: "https://near.drpc.org", note: "gateway: light client methods unavailable" },
  { id: "blockpi", label: "BlockPI", url: "https://near.blockpi.network/v1/rpc/public", note: "public path needs a key", keyed: true },
  { id: "ankr", label: "Ankr", url: "https://rpc.ankr.com/near", note: "requires an API key", keyed: true },
  { id: "zan", label: "ZAN", url: "https://api.zan.top/node/v1/near/mainnet", note: "public path needs a key", keyed: true },
  { id: "getblock", label: "GetBlock", url: null, note: "needs an API key", keyed: true },
  { id: "nodereal", label: "NodeReal", url: null, note: "needs an API key", keyed: true },
  { id: "nownodes", label: "NOWNodes", url: null, note: "needs an API key", keyed: true },
  { id: "quicknode", label: "QuickNode", url: null, note: "needs an account", keyed: true },
  { id: "lava", label: "Lava", url: null, note: "paid only" },
  { id: "tatum", label: "Tatum", url: null, note: "needs an API key", keyed: true },
  { id: "allthatnode", label: "All That Node", url: null, note: "needs an API key", keyed: true },
  { id: "lavenderfive", label: "Lavender.Five", url: null, note: "needs an account", keyed: true },
  { id: "node101", label: "node101", url: null, note: "paid only" },
  { id: "zeeve", label: "Zeeve", url: null, note: "paid only" },
];

export type ProbeStatus = "ok" | "no-proofs" | "unreachable" | "http-error";

export interface ProbeResult {
  url: string;
  label: string;
  status: ProbeStatus;
  /** Human sentence for the UI — what happened, in words a user can act on. */
  detail: string;
  ms: number;
}

const TIMEOUT_MS = 12_000;

async function call(url: string, method: string, params: unknown): Promise<any> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "probe", method, params }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const body = await response.json().catch(() => null);
  if (!body) throw new Error(`HTTP ${response.status}`);
  if (body.error) {
    const name = body.error?.cause?.name ?? body.error?.message ?? "error";
    throw new Error(String(name));
  }
  return body.result;
}

/**
 * Can this endpoint be used to verify? Two questions, both answered by asking it: does it respond at
 * all (a gateway that blocks the browser looks exactly like a dead host), and does it serve a light
 * client block — the one thing a verifier cannot work without.
 *
 * `anchorHash` should be an epoch-start block (a pin). Asking most nodes for the block *after* the
 * current head is not a fair question — they answer with an empty object, which says nothing about
 * whether they serve proofs — so the pin is asked first, and the head only as a fallback.
 */
export async function probeProvider(url: string, label = url, anchorHash?: string): Promise<ProbeResult> {
  const started = performance.now();
  const done = (status: ProbeStatus, detail: string): ProbeResult => ({
    url,
    label,
    status,
    detail,
    ms: Math.round(performance.now() - started),
  });

  let head: any;
  try {
    head = await call(url, "block", { finality: "final" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/Failed to fetch|NetworkError|load failed/i.test(message)) {
      return done("unreachable", "the browser could not reach it (offline, or no CORS headers)");
    }
    if (/apikey|api key|unauthoriz|authenticat|forbidden|403|401|path not match|request check|invalid key|missing key/i.test(message)) {
      return done("http-error", "its public path is not open — it wants an API key");
    }
    return done("http-error", message.slice(0, 80));
  }

  const headHash = head?.header?.hash;
  if (!headHash) return done("no-proofs", "it answered, but not with a block header");

  const anchors: Array<{ hash: string; pinned: boolean }> = [];
  if (anchorHash) anchors.push({ hash: anchorHash, pinned: true });
  if (headHash !== anchorHash) anchors.push({ hash: headHash, pinned: false });

  let detail = "it does not expose the light client methods";
  for (const anchor of anchors) {
    try {
      const view = await call(url, "next_light_client_block", { last_block_hash: anchor.hash });
      if (view?.inner_lite) return done("ok", "responds and serves light client blocks");
      detail = anchor.pinned
        ? "it answered, but no longer keeps the pinned epoch's next light client block"
        : "it answered, but returned no light client block";
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/not available|not found|MethodNotFound|-32601|does not exist|unsupported/i.test(message)) {
        return done("no-proofs", "it does not expose the light client methods");
      }
      if (/rate limit|too many|429/i.test(message)) {
        return done("no-proofs", "it is rate limiting right now");
      }
      detail = message.slice(0, 80);
    }
  }
  return done("no-proofs", detail);
}
