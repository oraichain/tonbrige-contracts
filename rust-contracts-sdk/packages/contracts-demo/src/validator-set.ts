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
  console.log("get master info");
  const master = await client.getMasterchainInfo();
  console.log("master", master);

  // key block. Got this by querying a block, then deserialize it, then find prev_key_block_seqno
  // it has to be a key block to include validator set & block extra to parse into the contract
  let initBlockSeqno = master.last.seqno;
  while (true) {
    const fullBlock = await client.getFullBlock(initBlockSeqno);
    const initialBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initBlockSeqno);
    // get block
    const block = await engine.query(Functions.liteServer_getBlock, {
      kind: "liteServer.getBlock",
      id: {
        kind: "tonNode.blockIdExt",
        ...initialBlockInformation
      }
    });

    const parsedBlock = await parseBlock(block);
    if (!parsedBlock.info.key_block) {
      initBlockSeqno = parsedBlock.info.prev_key_block_seqno;
      continue;
    }
    console.log("boc: ", block.data.toString("hex"));
    console.log("parsed block: ", parsedBlock);
    // const [rootCell] = await TonRocks.types.Cell.fromBoc(block.data.toString("hex"));
    // const parsedBlockData: string[] = await buildValidatorsData(rootCell);
    // console.dir(parsedBlockData[0]);
    // console.log(parsedBlock.extra.custom.config.config.map.get("22")); // 34 in decimals. 34 is the index of validator set
    break;
  }

  engine.close();
})();
