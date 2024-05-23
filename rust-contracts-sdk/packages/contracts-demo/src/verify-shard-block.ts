import { Cell } from "@ton/core";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions } from "ton-lite-client/dist/schema";
import TonWeb from "tonweb";

function intToIP(int: number) {
  var part1 = int & 255;
  var part2 = (int >> 8) & 255;
  var part3 = (int >> 16) & 255;
  var part4 = (int >> 24) & 255;

  return part4 + "." + part3 + "." + part2 + "." + part1;
}

// verifying shard block: https://docs.ton.org/develop/data-formats/proofs#shard-block
(async () => {
  const { liteservers } = await fetch("https://ton.org/global.config.json").then((data) => data.json());
  // Personal choice. Can choose a different index if needed
  const server = liteservers[1];

  const engines: LiteEngine[] = [];
  engines.push(
    new LiteSingleEngine({
      host: `tcp://${intToIP(server.ip)}:${server.port}`,
      publicKey: Buffer.from(server.id.key, "base64")
    })
  );
  const engine: LiteEngine = new LiteRoundRobinEngine(engines);
  const client = new LiteClient({ engine });
  const master = await client.getMasterchainInfo();

  // Create Client
  const initKeyBlockSeqno = master.last.seqno;
  const fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  const minimalBlockShards = await client.getAllShardsInfo({ ...initialKeyBlockInformation });
  const tonWeb = new TonWeb();
  const blockShards = await tonWeb.provider.getBlockShards(initKeyBlockSeqno);
  console.log(blockShards);
  const shardInfo = await engine.query(Functions.liteServer_getShardInfo, {
    kind: "liteServer.getShardInfo",
    id: {
      kind: "tonNode.blockIdExt",
      ...initialKeyBlockInformation
    },
    workchain: 0,
    shard: blockShards.shards[0].shard,
    exact: true
  });
  console.log(shardInfo);
  engine.close();
})();
