import { Cell, parseValidatorSet } from "@ton/ton";
import "dotenv/config";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions } from "ton-lite-client/dist/schema";
import { intToIP } from "./common";

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

  // const endpoint = await getHttpEndpoint({ network: "mainnet" });
  // Create Client
  const initKeyBlockSeqno = master.last.seqno;
  const fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  // console.log(initialKeyBlockInformation);
  const blockConfig = await client.getConfig(initialKeyBlockInformation, {
    awaitSeqno: initialKeyBlockInformation.seqno
  });
  const validatorSetCell = blockConfig.config.get(34);

  // TODO: need to proof that this validator set is valid
  const validators = parseValidatorSet(validatorSetCell.beginParse());
  console.dir(validators, { depth: null });

  // get block
  const configRaw = await engine.query(Functions.liteServer_getConfigAll, {
    kind: "liteServer.getConfigAll",
    id: {
      kind: "tonNode.blockIdExt",
      ...initialKeyBlockInformation
    },
    mode: 0
  });
  console.log("config raw: ", Cell.fromBoc(configRaw.configProof)[0].toBoc().toString("hex"));

  engine.close();
})();
