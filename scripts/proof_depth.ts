// How deep can a light client proof be obtained? Probes the same transaction-finding logic at
// increasing depths and reports the first depth where the node refuses to serve a proof.
//
//   npx tsx scripts/proof_depth.ts
import { NearRpc } from "../src/rpc.js";
import { b58encode } from "../src/base58.js";
import { lightClientBlockHash } from "../src/light-client.js";

const rpc = new NearRpc(process.env.UPSTREAM_RPC ?? "https://free.rpc.fastnear.com");
const final = await rpc.finalBlock();
const head = Number(final.header.height);
const view: any = await rpc.nextLightClientBlock((await rpc.block(head - 3)).header.hash);
const headHash = b58encode(lightClientBlockHash(view));
console.log(`head ${head}, light client head ${view.inner_lite.height}\n`);

for (const back of [1_000, 20_000, 50_000, 80_000, 100_000, 200_000]) {
  let found: { hash: string; signer: string } | null = null;
  try {
    for (let offset = back; offset < back + 200 && !found; offset += 10) {
      const block = await rpc.block(head - offset);
      for (const chunkInfo of block.chunks ?? []) {
        const chunk = await rpc.call("chunk", { block_id: block.header.hash, shard_id: chunkInfo.shard_id }).catch(() => null);
        const tx = (chunk as any)?.transactions?.find((t: any) => t.signer_id);
        if (tx) {
          found = { hash: tx.hash, signer: tx.signer_id };
          break;
        }
      }
    }
  } catch (error) {
    console.log(`${String(back).padStart(7)} blocks back: could not read the block (${(error as Error).message.slice(0, 50)})`);
    continue;
  }
  if (!found) {
    console.log(`${String(back).padStart(7)} blocks back: no transaction found nearby`);
    continue;
  }
  try {
    await rpc.lightClientProofTransaction(found.hash, found.signer, headHash);
    console.log(`${String(back).padStart(7)} blocks back: proof OK   (${found.hash.slice(0, 10)}…)`);
  } catch (error) {
    console.log(`${String(back).padStart(7)} blocks back: proof REFUSED — ${(error as Error).message.slice(0, 70)}`);
  }
}
