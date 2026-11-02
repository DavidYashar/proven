/** Minimal NEAR JSON-RPC client (works in Node 18+ and browsers). */

import { bytesToBase64 } from "./bytes.js";

export interface RpcOptions {
  /** Endpoint to talk to. Any RPC will do — that is the point. */
  url: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  /** Attempts for transient provider errors (rate limits, deprecation banners). Default 3. */
  retries?: number;
}

const TRANSIENT = /rate limit|too many requests|deprecated|temporarily|server error|503|429/i;

// A provider that is throttling or timing out has not answered anything. Match the error *type*
// rather than its message: fastnear labels data errors with the generic message "Server error",
// so a message match would retry a perfectly good answer into a timeout.
const TRANSIENT_CAUSE = /RATE_LIMIT|TIMEOUT|UNAVAILABLE|OVERLOADED/i;

export class NearRpc {
  readonly url: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly retries: number;

  constructor(options: RpcOptions | string) {
    const opts = typeof options === "string" ? { url: options } : options;
    this.url = opts.url;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.retries = opts.retries ?? 3;
  }

  async call<T = any>(method: string, params: unknown): Promise<T> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        return await this.callOnce<T>(method, params);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (!TRANSIENT.test(lastError.message) || attempt === this.retries - 1) throw lastError;
        await new Promise((r) => setTimeout(r, 1200 * 2 ** attempt));
      }
    }
    throw lastError ?? new Error(`${method}: failed`);
  }

  private async callOnce<T>(method: string, params: unknown): Promise<T> {
    const body = await this.request<T>(method, params);
    if (body.error) {
      const cause = body.error?.cause?.info?.error_message ?? body.error?.message ?? "rpc error";
      throw new Error(`${method}: ${cause}`);
    }
    if (body.result === undefined) throw new Error(`${method}: empty response`);
    return body.result;
  }

  /**
   * The upstream's JSON-RPC envelope, errors included. A proxy must forward an error the node
   * raised (e.g. "unknown block") as an error, not invent its own. Only transport failures and
   * throttling are exceptions here, because a throttled provider has not answered anything.
   */
  async callEnvelope(method: string, params: unknown): Promise<{ result?: any; error?: any }> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        const body = await this.request(method, params);
        const causeName = String(body.error?.cause?.name ?? body.error?.name ?? "");
        if (body.error && TRANSIENT_CAUSE.test(causeName)) throw new Error(`${method}: ${causeName}`);
        return body;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (!TRANSIENT.test(lastError.message) || attempt === this.retries - 1) throw lastError;
        await new Promise((r) => setTimeout(r, 1200 * 2 ** attempt));
      }
    }
    throw lastError ?? new Error(`${method}: failed`);
  }

  private async request<T>(method: string, params: unknown): Promise<{ result?: T; error?: any }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    // Call `fetch` through a local binding: a bare global `fetch` must not be invoked as a method
    // (`this.fetchImpl(...)` sets `this` to the client and browsers reject it with
    // "Illegal invocation", which Node tolerates — so this only breaks in the browser).
    const fetchImpl = this.fetchImpl;
    try {
      const response = await fetchImpl(this.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "proven", method, params }),
        signal: controller.signal,
      });
      if (response.status >= 500 || response.status === 429) {
        throw new Error(`${method}: server error ${response.status}`);
      }
      return (await response.json()) as { result?: T; error?: any };
    } finally {
      clearTimeout(timer);
    }
  }

  finalBlock(): Promise<any> {
    return this.call("block", { finality: "final" });
  }

  block(blockId: number | string): Promise<any> {
    return this.call("block", { block_id: blockId });
  }

  nextLightClientBlock(lastBlockHash: string): Promise<any | null> {
    return this.call("next_light_client_block", { last_block_hash: lastBlockHash });
  }

  /**
   * The proof method was promoted out of its `EXPERIMENTAL_` prefix; older nodes only expose the
   * prefixed name, so try the stable one first and fall back.
   */
  private async lightClientProof(params: Record<string, unknown>): Promise<any> {
    try {
      return await this.call("light_client_proof", params);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!/method not found|MethodNotFound/i.test(message)) throw error;
      return this.call("EXPERIMENTAL_light_client_proof", params);
    }
  }

  lightClientProofTransaction(transactionHash: string, senderId: string, lightClientHead: string): Promise<any> {
    return this.lightClientProof({
      type: "transaction",
      light_client_head: lightClientHead,
      transaction_hash: transactionHash,
      sender_id: senderId,
    });
  }

  lightClientProofReceipt(receiptId: string, receiverId: string, lightClientHead: string): Promise<any> {
    return this.lightClientProof({
      type: "receipt",
      light_client_head: lightClientHead,
      receipt_id: receiptId,
      receiver_id: receiverId,
    });
  }

  /** Contract storage with a trie proof (the only `query` variant that returns proofs). */
  viewStateWithProof(accountId: string, blockId: number, prefix?: Uint8Array): Promise<any> {
    return this.call("query", {
      request_type: "view_state",
      account_id: accountId,
      block_id: blockId,
      prefix_base64: prefix ? bytesToBase64(prefix) : "",
      include_proof: true,
    });
  }

  txStatus(transactionHash: string, senderAccountId: string): Promise<any> {
    return this.call("EXPERIMENTAL_tx_status", {
      tx_hash: transactionHash,
      sender_account_id: senderAccountId,
      wait_until: "FINAL",
    });
  }

  /** Transactions of a block, discovered through chunk RPCs (block view may omit them). */
  async findTransaction(height: number): Promise<{ hash: string; signer: string } | null> {
    const block = await this.block(height);
    for (const chunkInfo of block.chunks ?? []) {
      let chunk: any;
      try {
        chunk = await this.call("chunk", { block_id: block.header.hash, shard_id: chunkInfo.shard_id });
      } catch {
        continue;
      }
      const tx = (chunk.transactions ?? []).find((t: any) => t.signer_id);
      if (tx) return { hash: tx.hash, signer: tx.signer_id };
    }
    return null;
  }
}
