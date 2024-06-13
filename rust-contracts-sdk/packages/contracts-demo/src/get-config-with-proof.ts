import TonRocks from "@oraichain/tonbridge-utils";
import { loadShardStateUnsplit } from "@oraichain/tonbridge-utils/build/blockchain/BlockParser";
import { Cell } from "@ton/core";
import assert from "assert";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions } from "ton-lite-client/dist/schema";

function intToIP(int: number) {
  var part1 = int & 255;
  var part2 = (int >> 8) & 255;
  var part3 = (int >> 16) & 255;
  var part4 = (int >> 24) & 255;

  return part4 + "." + part3 + "." + part2 + "." + part1;
}

// this logic is for proofing block header: https://docs.ton.org/develop/data-formats/proofs#block-header
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

  const initKeyBlockSeqno = master.last.seqno;
  const fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  const config = await client.engine.query(Functions.liteServer_getConfigAll, {
    kind: "liteServer.getConfigAll",
    id: {
      kind: "tonNode.blockIdExt",
      ...initialKeyBlockInformation
    },
    mode: 0
  });
  console.log("config: ", config);
  const stateProofCell = Cell.fromBoc(config.stateProof)[0].refs[0];
  const stateProofCellHash = stateProofCell.hash(0);
  assert(Buffer.from(stateProofCellHash).toString("hex") === initialKeyBlockInformation.rootHash.toString("hex"));

  const merkleUpdateOfConfigState = stateProofCell.refs[2];
  const slice = merkleUpdateOfConfigState.beginParse(true);
  slice.loadBuffer(1);
  slice.loadBuffer(32);
  const newStateHash = slice.loadBuffer(32);

  const configProofCell = Cell.fromBoc(config.configProof)[0].refs[0];
  const configProofHash = configProofCell.hash(0);
  assert(Buffer.from(newStateHash).toString("hex") === Buffer.from(configProofHash).toString("hex"));

  const configProofCellTonRocks = await TonRocks.types.Cell.fromBoc(config.configProof);
  const configStateData = loadShardStateUnsplit(configProofCellTonRocks[0].refs[0]);
  console.log("config state data: ", configStateData.custom.config.config);
  engine.close();
})();
