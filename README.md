# proven

**The NEAR RPC you don't have to trust.**

`proven` verifies NEAR JSON-RPC answers **client-side** — in Node or in a browser — against the
signatures of the validators that produced them. If the RPC lies, `proven` says so.

```bash
git clone <this repo> && cd proven
npm ci && npm run build
node dist/cli.js tx <transaction_hash> <signer_id> --rpc https://any-near-rpc.example
```

> The package name `proven` is taken on npm by an unrelated library, so this is run from a clone
> (or `npm link`), not with `npx proven`.

```text
transaction 6UxC9DcHMi63NpgSzWcYP5439Nf9iJS7vxzh1MrQqjLY
  light client head  221486613 (69.6% of stake signed)
  ✓ approvals signed by >2/3 of validator stake — 69.6% of 555954883M NEAR
  ✓ validator set committed by next_bp_hash — 100 validators
  ✓ verified head is the canonical block at its height — height 221486613
  ✓ proof's block header recomputes to the outcome's block_hash
  ✓ proof is for the requested transaction
  ✓ execution outcome is committed by the block's outcome_root — 2 leaf hash(es), 3+4 path steps
  ✓ block is committed by the trusted head's block_merkle_root — 20 path steps

  VERIFIED
```

## Try it in 60 seconds

Every step below is a self-contained "do X → see Y". Steps 2, 5 and 6 print `trust: anchored`,
which needs a pin for the *current* epoch — run `npm run checkpoint` first (a pin covers one ~12h
epoch; without one the same proofs still verify, but say `rpc-asserted` instead).

1. **Install and run the offline vectors** (no network): `npm ci && npm test` → `pass 22, fail 0`.
2. **Verify a real transaction** — `npx tsx src/cli.ts tx <hash> <signer>` (get a `<hash> <signer>`
   pair from `npx tsx src/cli.ts find <height>`) → every check prints `✓`, verdict `VERIFIED`.
3. **Watch it catch a liar** — `npm run test:attack` → an RPC that invents its own validator set is
   accepted as `rpc-asserted` with no checkpoint, then rejected once the checkpoint is pinned.
4. **Watch a live endpoint lie** — `npm run test:live` → rewrites an outcome and fakes finality
   against mainnet data; both are caught, the honest one passes.
5. **Verify contract storage** — `npx tsx src/cli.ts state mpc-prover-0_4_12.bridge.near STATE` →
   the stored `STATE` bytes are proven up to the signed state root.
6. **Run the verifying proxy** — `npm run proxy` (listens on `:8080`), then send any NEAR JSON-RPC
   request to `http://localhost:8080` → the response carries `x-proven-verified: true` and
   `x-proven-trust: anchored`; `curl http://localhost:8080/status` shows counters.
7. **Open the browser app** — `npm run web:dev`, then click *Verify* → proofs are checked inside the
   page; switch *endpoint behaviour* to "rewrites the outcome" / "forges a validator set" / "rewrites
   stored state" and click *Verify* again → `REJECTED`.
8. **Re-pin whenever the epoch turns over** — `npm run checkpoint` → `trust: anchored` again.
9. **Deploy it** — push the repo and apply `render.yaml` (one Node service for the proxy, one static
   site for the app).

A machine can also import the library directly:

```ts
const result = await verifyTransaction({ hash, signerId, rpc: "https://any-near-rpc.example" });
if (!result.verified || result.trust !== "anchored") throw new Error("do not trust this answer");
```

## How it works — four hashes

```
transaction outcome  ──outcome_root──────────▶  block header
block header         ──block_merkle_root─────▶  light-client head
light-client head    ──ed25519 approvals─────▶  >2/3 of staked NEAR signed it
validator set        ──next_bp_hash + a pin──▶  these are the real producers
```

The RPC may supply every byte, but nothing is believed until a hash matches. A lying endpoint can
only make verification **fail**, never falsely succeed.

### The pin, and why it expires

To check a signature you need the signer's public key — ask the RPC and a hostile one simply invents
100 validators and signs with its own keys: a **perfect forgery**, since every hash and signature is
self-consistent. That is the "forges a validator set" row in the demo table below.

A **pin** (checkpoint) is that key list, recorded earlier from a moment you trusted: the producers of
one epoch, with the hash proving the file wasn't edited. Now the RPC cannot swap the keys, and a lie
needs >2/3 of NEAR's real stake.

NEAR replaces its producer set every epoch (~12 h), so a pin covers exactly one epoch. When it goes
stale, `proven` doesn't pretend: it drops to `quorum`/`rpc-asserted` and says which. `proven` never
auto-pins behind your back — that would silently re-accept the attacker's set and destroy the whole
guarantee.

## Tracks it leans on

`open` (primary), `privacy` (verification without asking anyone to trust a server), `security`
(AI agents and policy engines need answers they can check), `agents` (an agent that pays for data
should be able to verify that data). It uses NEAR's **light client protocol (NEP-25)** — ed25519
validator approvals, `next_bp_hash` handoffs, `inner_rest_hash`, `chunk_headers_root`, trie state
proofs — with no new chain, token, or trusted party.

## Why

Every NEAR wallet, explorer, indexer and AI agent reads the chain through an RPC it does not
control. A single compromised or buggy endpoint can answer with a transaction that never happened,
a balance that is not yours, or a "final" block nobody signed. NEAR already ships the cryptography
to prevent this — **light client proofs** — but almost nobody can use it: there was no browser or
Node verifier for NEP-25 headers and execution-outcome proofs, and none of the four NEAR explorer
stacks (near.org, NearBlocks, PikesPeak, near.rocks) verify what they display.

`proven` is that missing client.

## What it proves

| Layer | Primitive | Source of truth |
|---|---|---|
| Header | block hash from `LightClientBlockView` | nearcore `block_header.rs`, NEP-25 |
| Finality | ed25519 approvals over the endorsement message, >2/3 stake | `core/primitives/src/merkle.rs`, `light_client.rs` |
| Validator set | `sha256(borsh(next_bps)) == next_bp_hash` | NEP-25 rule 6 |
| Execution | `outcome_proof` → shard root → block `outcome_root` | `transaction.rs::to_hashes`, `test-loop-tests/.../light_client.rs` |
| Inclusion | block hash → trusted head `block_merkle_root` | `block_proof` |
| Contract storage | trie path → verified chunk `prev_state_root` → `chunk_headers_root` → `inner_rest_hash` | `raw_node.rs`, `block_header.rs`, `block.rs` |

The result: *any* RPC can serve the data, and the client independently checks that >2/3 of NEAR's
staked validators agreed with it.

## Contract storage proofs

```bash
proven state mpc-prover-0_4_12.bridge.near STATE
```

```text
contract storage mpc-prover-0_4_12.bridge.near ["STATE"]
  trust              anchored (pinned validator set)
  ✓ approvals signed by >2/3 of validator stake — 67.1% of 556038786M NEAR
  ✓ stored value matches the leaf's commitment — 26 bytes of 26 committed
  ✓ block header matches the head's inner_rest_hash — protocol 86, 4643 bytes
  ✓ chunk headers reproduce chunk_headers_root — 10 chunks
  ✓ proof folds to a state root signed by the head's validators — shard 4, block 221535726

  VERIFIED
```

This is the deepest thing `proven` does. The chain from a storage byte to validator signatures is
five links long, and every link is a hash that either matches or doesn't:

```text
value bytes                     ── trie path ──▶  shard prev_state_root
shard prev_state_root           ── merklize ──▶   chunk_headers_root
chunk_headers_root              ── borsh ──▶      inner_rest_hash      (field of BlockHeaderInnerRestV6)
inner_rest_hash                 ── light client block ──▶  2/3 of staked validators
```

`src/block-header.ts` does the middle three: it re-encodes `BlockHeaderInnerRestV6` from the JSON
header and checks it against the head's `inner_rest_hash`, then recomputes every chunk's hash from
its *inner* header and merklizes `ChunkHashHeight(chunk_hash, height_included)` into
`chunk_headers_root`. A lying endpoint can't inject its own state root, because it would have to
invert sha256 twice.

Honest limitation: `view_account` returns **no proof** (only `view_state` does), so an account's
*native balance* cannot be proven through the public RPC at all; what is provable is what a contract
stores — an FT balance in the contract's own state, an escrow record, a DAO vote, an NFT owner.


## Trust levels — what "verified" actually means

Verification is only as strong as where the validator set came from, so `proven` refuses to
overstate it. Every result carries a `trust` field:

| `trust` | How the signer set was established | What an attacker needs |
|---|---|---|
| `anchored` | Pinned checkpoint (`proven checkpoint`) — >2/3 of the producers you pinned must have signed this head | >2/3 of NEAR's **real** stake |
| `quorum` | Two or more independent RPCs returned the same light client block, and approvals were checked against the set that actually signs this epoch (fetched from the chain) | every provider colluding |
| `rpc-asserted` | The endpoint supplied both the head and the keys; approvals are still checked, but a hostile node could have invented the whole chain | nothing |

That last row is why checkpoints exist. `tests/forge-head.ts` demonstrates it end to end: a liar
generates validators with implausible stake, signs a fabricated head with its own keys, and the
forgery **passes every hash check** — because it is self-consistent. Pointed at that node without a
checkpoint, `proven` reports `rpc-asserted` and never claims more. With a pinned checkpoint the
signatures are checked against *your* keys, so the forgery scores 0% and is rejected.

`trust` and `verified` are separate answers: a stale pin lowers `trust` (say `anchored` → `quorum`)
but never turns a valid proof into a failed one. Only cryptography sets `verified`.

```bash
proven checkpoint --out checkpoints/mainnet.json   # pin the producers that sign this epoch
proven head --require-anchor                      # fail instead of silently downgrading
proven tx <hash> <signer> --rpcs https://a,https://b   # quorum across providers
```

Checkpoints expire with the epoch (~12h), which is why shipping one is a convenience, not a
guarantee: refresh with `proven checkpoint`, and run the strict path in CI. `proven` deliberately
does **not** re-pin automatically — an automatic re-pin would accept whatever set the endpoint
claims, which is exactly the forgery the pin exists to stop.

## Library use

```ts
import { verifyTransaction, decodeSuccessValue, parseCheckpoint } from "proven";
import { readFileSync } from "node:fs";

const checkpoint = parseCheckpoint(readFileSync("checkpoints/mainnet.json", "utf8"));
const result = await verifyTransaction(txHash, signerId, {
  rpc: "https://free.rpc.fastnear.com",
  checkpoint,
});

if (!result.verified) {
  for (const check of result.checks.filter((c) => !c.ok)) console.warn("failed:", check.name);
  throw new Error("this RPC lied to you");
}
console.warn(`trust: ${result.trust}`); // anchored | quorum | rpc-asserted
console.log(decodeSuccessValue(result.value.outcome));
```

Nothing in the flow trusts the endpoint: a malicious RPC can make verification **fail**, never
succeed. The only seed of trust is a checkpoint you pin; without one the tool is honest about it and
verifies against the producer set it can fetch, reporting `rpc-asserted`.

## Demo: catching a lying RPC

```bash
npm test            # 22 offline vector tests, no network
npm run test:attack # a forged validator set that only a checkpoint can catch
npm run test:live   # an RPC that tampers with responses on the wire
npx tsx scripts/bench.ts      # latency of the proxy versus a direct RPC
npx tsx scripts/proof_depth.ts # how far back a proof can be obtained
```

```text
honest RPC                         → accepted
RPC that rewrites the outcome      → rejected
    ✗ execution outcome is committed by the block's outcome_root
RPC that fakes finality            → rejected
    ✗ approvals signed by >2/3 of validator stake

no checkpoint        → trust rpc-asserted, verified=true    ← forgery is self-consistent
pinned checkpoint    → verifier rejects it
    ✗ approvals signed by >2/3 of validator stake — 0% of 556906176M NEAR, 3 matched no key
```

`tests/demo.ts` proxies a real RPC and tampers with responses; `tests/forge-head.ts` runs a node
that fabricates an entire validator set and signs with it.

## Drop-in verifying proxy

The library is only half the story — nobody rewrites their RPC client. `proven proxy` is a
JSON-RPC endpoint that verifies what it forwards, so **changing one URL** is the whole integration:

```bash
UPSTREAM_RPC=https://free.rpc.fastnear.com PROVEN_CHECKPOINT=checkpoints/mainnet.json npm run proxy
# proven proxy listening on :8080
```

```bash
curl -i -sS http://localhost:8080 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"EXPERIMENTAL_tx_status",
       "params":{"tx_hash":"<hash>","sender_account_id":"<signer>"}}' | head -12
```

```text
HTTP/1.1 200 OK
access-control-allow-origin: *
access-control-expose-headers: x-proven-verified, x-proven-trust, ...
x-proven-verified: true
x-proven-trust: anchored
x-proven-method: EXPERIMENTAL_tx_status
x-proven-detail: 221536521 · 76.54% stake
```

The payload is **byte-for-byte the upstream's result**, so `near-api-js`, `fetch`, and wallet code
keep working untouched. The verdict rides in headers.

| Verifiability | Methods | Verdict header |
|---|---|---|
| full proof | `tx`, `EXPERIMENTAL_tx_status`, `query` (`view_state` + `include_proof`) | `x-proven-verified: true`, trust `anchored`/`quorum` |
| self-consistent | `block` (header hash recomputed from its own contents) | `x-proven-verified: self` |
| none | everything else | `x-proven-verified: unverified` — or `rejected` in strict mode |

A response that **fails** verification is never handed back: the proxy returns a JSON-RPC error
(`-32002`) instead, so a lying upstream cannot inject data silently. `PROVEN_STRICT=1` additionally
refuses methods that have no proof primitive at all, rather than forwarding them unverified.

### Cost

Measured against `free.rpc.fastnear.com` from a consumer connection (`npx tsx scripts/bench.ts`,
9 samples, median):

| Call | direct | via proxy |
|---|---|---|
| `block` (header hash re-checked locally) | 114 ms | 87 ms |
| `EXPERIMENTAL_tx_status` (full light client proof) | 105 ms | **168 ms** |

So a verified transaction costs ~60 ms more than an unverified one: one extra proof fetch plus a few
milliseconds of ed25519 and sha256. The head is resolved once and reused for 5 s — before that cache
the same call measured **685 ms median, 2.4 s p90**, because every request re-resolved it with six
RPC calls.

Verifying in bulk should not use the proxy at all: resolve one head and reuse it.

```ts
const head = await resolveHead({ rpcs: [rpc], checkpoint });
for (const tx of batch) await verifyTransaction(tx.hash, tx.signer, { rpc, checkpoint, resolvedHead: head });
```

`GET /status` reports the live head, the pinned checkpoint, the active upstream and counters; `GET /health`
is there for platform health checks. CORS is open, so a browser can talk to it directly.

Upstream errors are **forwarded**, not masked: if the node answers `unknown block`, the caller gets
that error with `x-proven-verified: false`. Only a transport failure (nothing answered) becomes a
`502`.

`UPSTREAM_RPC` accepts a comma-separated list: the first entry is primary, the rest are failover,
and the last one that worked is tried first, so one flaky provider is never visible to the caller.
Only `free.rpc.fastnear.com` and `rpc.mainnet.near.org` answer `next_light_client_block` publicly —
`near.drpc.org` and `1rpc.io/near` reject it, which makes them useless as upstreams for a verifier.

Deploy both services with [render.yaml](./render.yaml) (Blueprint → this repo): a Node web service
for the proxy and a static site for the app, with `VITE_DEFAULT_RPC` pointing the app at the proxy.

The proxy is Node-only, so it is published on a separate entry point and never reaches the browser
bundle:

```ts
import { createProvenProxy } from "proven/proxy";   // server side
import { verifyTransaction } from "proven";         // any JS runtime
```

## Browser verifier

```bash
npm run web:dev     # http://localhost:5174
npm run web:build   # static bundle in web/dist (~89 kB, ~34 kB gzipped)
```

A single static page — no backend, no server of ours. Paste a transaction hash, or press
**Use a recent transaction**, and the checks run in the tab: proofs are fetched from whichever RPC
you point at and verified locally against ed25519 signatures.

The **endpoint behaviour** selector turns the same endpoint hostile *inside the page* (it wraps
`fetch` and tampers with responses before the verifier sees them), so the demo needs no rogue
server:

| Mode | What it does | Result |
|---|---|---|
| honest endpoint | passes responses through | **VERIFIED**, `anchored` |
| rewrites the outcome | swaps `executor_id` in the proof | **REJECTED** — outcome no longer matches `outcome_root` |
| fakes finality | strips all validator approvals | **REJECTED** — 0% of stake signed |
| forges a validator set | mints 100 validators, signs a fake head with its own keys | **REJECTED** — the signatures are checked against the *pinned* keys, so they match nothing |
| rewrites stored state | returns different bytes for a contract's storage key | **REJECTED** — value no longer hashes to the leaf |

The forgery is the interesting one: it satisfies every hash in the protocol, because it is
self-consistent. Only the pin separates it from the real chain. With a fresh pin it is rejected at
the signature check; **remove the pin and the same forgery verifies as `rpc-asserted`** — that
contrast is the CLI demo (`npm run test:attack`):

```text
no checkpoint        → trust rpc-asserted, verified=true    ← every signature checks out
pinned checkpoint    → 0% of 556906176M NEAR, 3 matched no key
```

Deploying is `npm run web:build` and uploading `web/dist` to any static host (Cloudflare Pages,
Netlify, Vercel, GitHub Pages). `base: "./"` is set so subpaths work.

Inside the app, "re-pin current set" stores a trust-on-first-use pin in `localStorage`; the pin
shipped in `checkpoints/mainnet.json` expires with the epoch, so the UI shows when it has gone stale
rather than silently pretending to be anchored.

## A note on NEAR's own docs

`docs/ChainSpec/LightClient.md` documents the outcome leaf as `sha256(borsh(execution_outcome))`.
That is **not** what nearcore implements. The real recipe (see `outcomeToHashes` in
`src/outcome.ts`) is:

```text
leaves   = [ tx_or_receipt_id,
             sha256(borsh(PartialExecutionOutcome)),   // logs and metadata excluded
             sha256(log_0), sha256(log_1), … ]
itemHash = sha256(borsh(Vec<Hash>)) = sha256(u32_le(len) ‖ leaves…)
chunk    = fold(itemHash, outcome_proof.proof)
block    = fold(sha256(chunk), outcome_root_proof) == block_header_lite.inner_lite.outcome_root
```

Because `metadata` (`ExecutionMetadata::V4`, `ProfileDataV3`) is excluded from
`PartialExecutionOutcome`, a browser verifier is practical at all. That single detail is the
difference between "possible" and "reimplement all of near-primitives".

## Scope

- ✅ transactions, receipts, and contract-call results (`SuccessValue`) — verified end-to-end today
- ✅ **failed** outcomes (`ExecutionStatus::Failure`) — `PartialExecutionStatus::Failure` has no
  payload, so a failed receipt hashes to a single status byte
- ✅ headers, finality, validator-set handoff, pinned checkpoints, multi-RPC quorum
- ✅ contract **storage** proofs (`view_state` trie proofs) — value → state root → chunk header →
  light client block, fully `anchored`
- ❌ account **balance** proofs — `view_account` returns no proof and NEAR exposes no account-record
  proof endpoint, so this is impossible without a protocol change

### How far back a proof reaches

Verification covers recent history, not an archive. Measured on mainnet (`npx tsx
scripts/proof_depth.ts`): a transaction 80,000 blocks back still produced a valid proof; a
week-old one is refused by the node. The binding constraints are the head's block merkle tree (a
proof must land inside the tree the head commits to) plus the provider's outcome retention — an
archival node pushes both out, a pruned public endpoint pulls them in. Contract-storage proofs are
limited the same way for historical block heights, while *current* state is always provable.

## Things we had to discover the hard way

Recorded because they are wrong or unstated in the obvious places, and anyone rebuilding this will
hit them:

1. **The documented outcome leaf is wrong.** `docs/ChainSpec/LightClient.md` says
   `sha256(borsh(execution_outcome))`; nearcore hashes a *list*
   `[id, sha256(borsh(PartialExecutionOutcome)), sha256(log)…]`.
2. **`metadata` is not part of the hash.** `PartialExecutionOutcome` excludes logs and
   `ExecutionMetadata` (so the V4 `ProfileDataV3` blob never needs re-encoding) — this is what makes
   a browser verifier practical at all.
3. **Failures are cheap to verify.** `PartialExecutionStatus::Failure = 1` carries no error payload,
   so a failed receipt is verifiable from a single byte even though the JSON view contains a large
   `TxExecutionError`.
4. **`LogEntry` is a plain `String`** in current nearcore; the old `{Hash}`/`{Len}` variants are gone,
   so log hashing is `sha256(utf8(log))` with no variants to handle.
5. **`block_proof` is empty when the proven block *is* the light client head.** Folding an empty path
   returns the block hash, which never equals `block_merkle_root` — inclusion holds by identity
   instead. Miss this and you reject the most common request ("verify the transaction I just sent").
6. **`next_bps` is the producer set of the *next* epoch**, not the view's own — despite reading like
   it belongs to the block you are holding. The signatures in `approvals_after_next` come from the
   *previous* epoch's `next_bps`. Verify against `view.next_bps` and you silently drop every validator
   whose position moved at the epoch boundary: 12–15 signatures lost, ~13% of stake under-counted, and
   perfectly valid heads flipping to `REJECTED` whenever real participation sits near 2/3. It passes
   for whole epochs — until the sets drift apart. It also means approvals must be attributed **by
   key**, not by index, because equal-stake validators are tie-broken independently per epoch.
7. **`next_light_client_block` always returns the latest final block**, whatever anchor you pass — it
   cannot walk epoch by epoch, so a light client must persist its head and poll.
8. **The proof method was promoted out of `EXPERIMENTAL_`**; older nodes only expose the prefixed name,
   so the client tries both.
9. **`fetch` must not be called as a method.** `this.fetchImpl(...)` binds `this` to the client and
   browsers throw `Illegal invocation`, while Node tolerates it — a bug that only appears once the
   library runs in a tab, which is exactly where a light client belongs.
10. **Browsers can reach NEAR RPCs directly.** `free.rpc.fastnear.com` and `near.drpc.org` send
    `Access-Control-Allow-Origin: *`, so verification needs no proxy. Not every provider serves
    `next_light_client_block` (dRPC does not), which is why quorum tolerates a provider dropping out.
11. **A trie proof node is plain `borsh(RawTrieNodeWithSize)`** and its hash is `sha256` of those
    bytes — there is no separate hash field to strip. Children are a `u16` bitmap followed by the
    present child hashes; leaf/extension keys use hex-prefix encoding where `0x10` means "odd".
12. **`view_state` proofs are against the *next* block.** The post-state of block `H` is committed as
    each chunk's `prev_state_root` in block `H+1`, so a proof requested at `H` folds to a root found
    in `H+1`'s chunk headers — never in `H`'s.
13. **`view_account` returns no proof** and there is no RPC for account-record proofs, so native
    balances are unprovable; contract storage is the provable surface.
14. **`header.prev_state_root` is not any chunk's state root** on a sharded chain — it cannot be used
    as the anchor for a shard's trie.
15. **No `Buffer`, no bound `fetch`, in a browser.** `Buffer` and `this.fetchImpl(...)` both work in
    Node and fail in a tab; the library now uses `Uint8Array` helpers and a local `fetch` binding.
16. **`BlockHeaderInnerRest` has nine versions.** The plain name is the *legacy V1*; protocol 86 uses
    **V6** (18 fields, `block_body_hash` first, no `chunks_included`/`challenges_root`). Encoding V1
    produced a plausible-looking hash that matched nothing.
17. **`chunk_headers_root` is not a merkle root of chunk headers.** It is
    `merklize(&[ChunkHashHeight(chunk_hash, height_included)])` — so you need each chunk's *hash*, not
    its borsh.
18. **`chunk_hash` is recomputable without the signature:**
    `sha256(sha256(borsh(inner)) ‖ encoded_merkle_root)`. That, plus the inner being
    `ShardChunkHeaderInner::V5` at protocol 86, is enough to rebuild the root from the chunk view.
19. **`CongestionInfo` uses a one-byte tag** even though the enum carries no `use_discriminant`
    attribute — found by trying both and watching which hash reproduced.
20. **A JSON-RPC error is not a proxy failure.** fastnear reports a bad `shard_id` as
    `HANDLER_ERROR / INVALID_SHARD_ID` with the message "Server error", so matching on message text
    turned a clean answer into retries, a fallback provider, and a 502. Match the error *type*
    (`cause.name`), not the prose.

## Status

Verified against live mainnet: 22/22 offline vector tests, 5/5 proxy tests, live tamper demos, a
receipt outcome with 5 log hashes, a failed outcome, a contract-storage proof anchored through
`inner_rest` and `chunk_headers_root`, and outcome proofs up to ~100,000 blocks deep. Historical
limits come from the node's outcome retention, not from the verifier.

The same code runs in three places, and all three have been exercised against mainnet: the library
(inside the CLI), the browser app (proofs checked in-page, no server), and the HTTP proxy (verdicts
on headers, `x-proven-verified: true|self|false`).

Known gaps:

1. **Balances are not provable** — no RPC returns an account-record proof.
2. **Header encoding is protocol-pinned.** `BlockHeaderInnerRestV6` + `ShardChunkHeaderInnerV5` match
   protocol 86; a future protocol bump must add the new variants (the code degrades to
   `quorum`/`rpc-asserted` instead of guessing, and the check says which hash failed).
3. **The pin expires every epoch** (~12h); refresh with `proven checkpoint`. Re-pinning is manual on
   purpose: re-pinning automatically would re-adopt whatever set the endpoint claims.
4. **Bridging an old pin is not possible over the public RPC.** `next_light_client_block` never walks
   forward one epoch at a time, so a client cannot chain from a week-old pin to today's head; it needs
   a pin for the current epoch (which is why the app has a one-click re-pin).
