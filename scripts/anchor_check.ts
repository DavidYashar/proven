import { b58encode, b58decode } from "../src/base58.js";
import { authenticateBlockRoots } from "../src/block-header.js";
import { bytesToHex } from "../src/bytes.js";
const RPC="https://free.rpc.fastnear.com";
async function jrpc(m:string,p:unknown){const r=await fetch(RPC,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:"1",method:m,params:p})});const j:any=await r.json();if(j.error)throw new Error(JSON.stringify(j.error).slice(0,140));return j.result;}
const head=await jrpc("block",{finality:"final"});
let lcb:any=null;
for (let back=0; back<6 && !lcb; back++){const b=await jrpc("block",{block_id:Number(head.header.height)-back});const c=await jrpc("next_light_client_block",{last_block_hash:b.header.hash});if(c?.inner_lite)lcb=c;}
const H=Number(lcb.inner_lite.height);
let block:any=null;
for (let i=0;i<20&&!block;i++){try{block=await jrpc("block",{block_id:H});}catch{await new Promise(r=>setTimeout(r,1200));}}
const roots = authenticateBlockRoots(block, lcb);
for (const c of roots.checks) console.log(`${c.ok?"PASS":"FAIL"}  ${c.name}${c.detail?" — "+c.detail:""}`);
console.log("computed chunk_headers_root:", roots.chunkHeadersRoot);
console.log("header chunk_headers_root  :", block.header.chunk_headers_root);
console.log("authenticated shards:", [...roots.stateRoots.keys()].join(","));
console.log("shard 4 root:", roots.stateRoots.get(4));
