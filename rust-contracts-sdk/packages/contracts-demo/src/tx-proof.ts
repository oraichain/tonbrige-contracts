import { Address, Cell, loadTransaction } from "@ton/core";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions } from "ton-lite-client/dist/schema";
import { intToIP, parseBlock } from "./common";

(async () => {
  const { liteservers } = await fetch("https://ton.org/global.config.json").then((data) => data.json());
  // Personal choice. Can choose a different index if needed
  const server = liteservers[0];

  const engines: LiteEngine[] = [];
  engines.push(
    new LiteSingleEngine({
      host: `tcp://${intToIP(server.ip)}:${server.port}`,
      publicKey: Buffer.from(server.id.key, "base64")
    })
  );
  const engine: LiteEngine = new LiteRoundRobinEngine(engines);
  const client = new LiteClient({ engine });

  // key block. Got this by querying a block, then deserialize it, then find prev_key_block_seqno
  // it has to be a key block to include validator set & block extra to parse into the contract
  let initBlockSeqno = 38194676;
  const fullBlock = await client.getFullBlock(initBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initBlockSeqno);
  // console.log("initial: ", initialKeyBlockInformation)
  // const minimalBlockShards = await client.getAllShardsInfo({ ...initialKeyBlockInformation });
  const blockInfo = await engine.query(Functions.liteServer_getBlock, {
    kind: "liteServer.getBlock",
    id: {
      kind: "tonNode.blockIdExt",
      ...initialKeyBlockInformation
    }
  });
  const parsedBlock = await parseBlock(blockInfo);
  for (let i = Number(parsedBlock.info.start_lt); i <= Number(parsedBlock.info.end_lt); i++) {
    try {
      const transaction = await client.getAccountTransaction(
        Address.parse("Ef9EEo2b2-xd5mHH4LgDk8uuK5qr20-Cz-zRs0CCOI3JeOmm"),
        i.toString(),
        initialKeyBlockInformation
      );
      const cell = Cell.fromBoc(transaction.transaction)[0].beginParse();
      const transactionDetails = loadTransaction(cell);
      if (Number(transactionDetails.lt) === i) {
        // console.log("transaction: ", transactionDetails);
        console.log("matched");
      }
    } catch (error) {}
  }

  engine.close();
})();
