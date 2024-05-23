import { Cell } from "@ton/core";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";

function intToIP(int: number) {
  var part1 = int & 255;
  var part2 = (int >> 8) & 255;
  var part3 = (int >> 16) & 255;
  var part4 = (int >> 24) & 255;

  return part4 + "." + part3 + "." + part2 + "." + part1;
}

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
  console.log("get master info");
  const master = await client.getMasterchainInfo();
  console.log("master", master);

  // const endpoint = await getHttpEndpoint({ network: "mainnet" });
  // Create Client
  const initKeyBlockSeqno = master.last.seqno;
  const fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  // console.log(initialKeyBlockInformation);
  const blockConfig = await client.getConfig(initialKeyBlockInformation);
  const validatorSetCell = blockConfig.config.get(34);
  console.log(validatorSetCell.toBoc());
  engine.close();
})();
