import { NearRpc } from "../src/rpc.js";

const rpc = new NearRpc("https://free.rpc.fastnear.com");
const final = await rpc.finalBlock();
const head = Number(final.header.height);
const earlier = await rpc.block(head - 5000);
const seconds = (BigInt(final.header.timestamp_nanosec) - BigInt(earlier.header.timestamp_nanosec)) / BigInt(1_000_000_000);
const perBlock = Number(seconds) / 5000;
console.log(
  `5000 blocks in ${Number(seconds)}s -> ${perBlock.toFixed(3)} s/block; a 43,200-block epoch is ${((perBlock * 43200) / 3600).toFixed(2)} h`,
);
