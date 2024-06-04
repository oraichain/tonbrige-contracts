import { Cell, loadShardStateUnsplit } from "@ton/core";
import { assert } from "console";
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
  const server = liteservers[2];

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
  const initKeyBlockSeqno = 38101265;
  let fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  const minimalBlockShards = await client.getAllShardsInfo({ ...initialKeyBlockInformation });
  const tonWeb = new TonWeb();
  const blockShards = await tonWeb.provider.getBlockShards(initKeyBlockSeqno);
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
  const shardCell = Cell.fromBoc(shardInfo.shardProof);
  const masterchainBlockMerkleProof = shardCell[0];
  // verify like in verify-block-header
  const merkleProofHash = masterchainBlockMerkleProof.refs[0].hash(0).toString("hex");
  const rootHash = initialKeyBlockInformation.rootHash.toString("hex");
  assert(merkleProofHash === rootHash);

  // parse merkle update based on: https://docs.ton.org/develop/data-formats/exotic-cells#merkle-update
  // shardCell[0].refs[0].refs[2] with refs[2] because the shardCell[0] contains block info: https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/crypto/block/block.tlb#L442
  // the block has 4 indexes, first one is global id, next is block info, and the 3rd one (2nd index count from 0) is state_update, which is merkle_update
  const merkleUpdateOfShardState = masterchainBlockMerkleProof.refs[0].refs[2];
  const slice = merkleUpdateOfShardState.beginParse(true);
  const cellType = slice.loadBuffer(1);
  const oldStateHash = slice.loadBuffer(32);
  const newStateHash = slice.loadBuffer(32);
  console.log(oldStateHash.toString("hex"), newStateHash.toString("hex"));

  // 2nd cell of shard proof
  const shardStateRaw = shardCell[1].refs[0];
  const merkleShardStateHash = shardStateRaw.hash(0).toString("hex");
  console.log(merkleShardStateHash);

  // after this assertion, we can trust the shard state data since we have verified the block header hash & the new hash of the shard state.
  assert(merkleShardStateHash === newStateHash.toString("hex"));

  const shardState = loadShardStateUnsplit(shardStateRaw.beginParse());
  // console.log(shardStateRaw.toBoc().toString("hex"));

  engine.close();
})();
