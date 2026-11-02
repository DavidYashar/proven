import { writeFileSync } from "node:fs";
const RPC="https://free.rpc.fastnear.com";
async function jrpc(m:string,p:unknown){const r=await fetch(RPC,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:"1",method:m,params:p})});const j:any=await r.json();if(j.error)throw new Error((j.error.cause?.info?.error_message||j.error.message||"").slice(0,120));return j.result;}
const ACCOUNT="mpc-prover-0_4_12.bridge.near";
const KEY=Buffer.from("STATE","utf8");
const head=await jrpc("block",{finality:"final"});
const H=Number(head.header.height)-3;
const q=await jrpc("query",{request_type:"view_state",account_id:ACCOUNT,prefix_base64:KEY.toString("base64"),include_proof:true,block_id:H});
const bH1=await jrpc("block",{block_id:H+1});
const fixture={ account:ACCOUNT, key:KEY.toString("base64"), blockHeight:q.block_height, blockHash:q.block_hash,
  values:q.values, proof:q.proof,
  chunksAtH1:bH1.chunks.map((c:any)=>({shard:c.shard_id, prev_state_root:c.prev_state_root})) };
writeFileSync("tests/fixtures/state-proof.json", JSON.stringify(fixture,null,1)+"\n");
console.log(`wrote state-proof.json: values=${q.values.length} proofNodes=${q.proof.length} block=${q.block_height}`);

// Header-anchoring fixture: the block whose chunk roots we must reproduce, plus the light client
// block that commits to it (so the offline test can re-derive both hashes).
const finalHead=await jrpc("block",{finality:"final"});
let lcb:any=null;
for (let back=0; back<8 && !lcb; back++){
  const b=await jrpc("block",{block_id:Number(finalHead.header.height)-back});
  const c=await jrpc("next_light_client_block",{last_block_hash:b.header.hash});
  if (c?.inner_lite) lcb=c;
}
const anchorHeight=Number(lcb.inner_lite.height);
let anchorBlock:any=null;
for (let i=0;i<20&&!anchorBlock;i++){
  try { anchorBlock=await jrpc("block",{block_id:anchorHeight}); } catch { await new Promise(r=>setTimeout(r,1200)); }
}
writeFileSync("tests/fixtures/block-anchor.json", JSON.stringify({
  height: anchorHeight,
  inner_rest_hash: lcb.inner_rest_hash,
  chunk_headers_root: anchorBlock.header.chunk_headers_root,
  header: anchorBlock.header,
  chunks: anchorBlock.chunks,
}, null, 1)+"\n");
console.log(`wrote block-anchor.json: block ${anchorHeight}, ${anchorBlock.chunks.length} chunks, protocol ${anchorBlock.header.latest_protocol_version}`);
