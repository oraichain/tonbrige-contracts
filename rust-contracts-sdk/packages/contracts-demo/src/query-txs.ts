import { Address, Cell, loadTransaction } from "@ton/core";
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

  // Create Client
  const txCount = 2;
  const master = await client.getMasterchainInfo();
  const addr = Address.parse("EQARXqu9hEzxsSP5ZdI5n3gv5XxFJQu8uPvEt0IJOwadzfA0");
  const accState = await client.getAccountState(addr, master.last);
  const lastHash = accState.lastTx.hash.toString(16);
  const accountTxs = await client.getAccountTransactions(
    addr,
    accState.lastTx.lt.toString(),
    Buffer.from(lastHash, "hex"),
    txCount
  );
  assert(accountTxs.ids.length === txCount);
  const txsCells = Cell.fromBoc(accountTxs.transactions);
  assert(txsCells.length === txCount);
  let prevTxHash = "";
  for (let i = 0; i < txsCells.length; i++) {
    const txCell = txsCells[i];
    const tx = loadTransaction(txCell.asSlice());
    console.log(tx.hash().toString("hex"));
    if (i > 0) {
      assert(prevTxHash === tx.hash().toString("hex"));
    }
    prevTxHash = tx.prevTransactionHash.toString(16);
    const masterchainRef = await client.engine.query(Functions.liteServer_getShardBlockProof, {
      kind: "liteServer.getShardBlockProof",
      id: {
        kind: "tonNode.blockIdExt",
        ...accountTxs.ids[i]
      }
    });
    console.log("masterchain ref: ", masterchainRef);
    const txDetail = await client.getAccountTransaction(addr, tx.lt.toString(), accountTxs.ids[i]);
    console.log(txDetail);
  }

  engine.close();
})();
