import { Cell } from "@ton/core";
import { assert } from "console";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";

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
  const header = await client.getBlockHeader(initialKeyBlockInformation);
  const cell = Cell.fromBoc(header.headerProof)[0];
  console.log(cell.refs[0].hash(0).toString("hex"));
  console.log(initialKeyBlockInformation.rootHash.toString("hex"));
  assert(cell.refs[0].hash(0).toString("hex") === initialKeyBlockInformation.rootHash.toString("hex"));
  engine.close();
})();
