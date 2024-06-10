import TonRocks from "@oraichain/tonbridge-utils";
import { Block } from "@oraichain/tonbridge-utils/build/blockchain";
import { assert } from "chai";
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
  const shardInfo = await client.lookupBlockByID({ seqno: 43884169, shard: "2000000000000000", workchain: 0 });
  const shardProof = await engine.query(Functions.liteServer_getShardBlockProof, {
    kind: "liteServer.getShardBlockProof",
    id: {
      kind: "tonNode.blockIdExt",
      ...shardInfo.id
    }
  });
  console.log(shardProof);
  let validatedShardBlockHashes = [];
  for (let i = 0; i < shardProof.links.length; i++) {
    const link = shardProof.links[i];
    // the first link is the shard block that is included in the masterchain block.
    // Assume that we already verified the masterchain block via validator signatures
    //
    const blockProofCell = await TonRocks.types.Cell.fromBoc(link.proof);
    const block = TonRocks.bc.BlockParser.parseBlock(blockProofCell[0].refs[0]);
    const blockRootHash = Buffer.from(blockProofCell[0].refs[0].getHash(0)).toString("hex");
    if (i === 0) {
      console.log("block root hash i === 0: ", blockRootHash, shardProof.masterchainId.rootHash.toString("hex"));
      // gotta make sure this proof is valid by checking if the block in the proof matches our trusted masterchain hash
      assert(blockRootHash === shardProof.masterchainId.rootHash.toString("hex"));
      // TODO: need to make sure on Rust this is a list of shardDescr because shard_hashes is a map
      const shardDescrs: any[] = Block._shardGetFromHashmap(block.extra.custom.shard_hashes, shardInfo.id.workchain);
      shardDescrs.forEach((shardDescr) => {
        console.log("shard root hash: ", Buffer.from(shardDescr.root_hash).toString("hex"));
        validatedShardBlockHashes.push(Buffer.from(shardDescr.root_hash).toString("hex"));
      });
    }
    if (i > 0) {
      console.log("block root hash i > 0: ", blockRootHash, validatedShardBlockHashes[i - 1]);
      // since the proofs are links from the wanted shard block to the masterchain block, hash of block_proof[i] must be in the validate shard block hashes
      assert(validatedShardBlockHashes.some((hash) => blockRootHash === hash));
      // since this block proof is validated, we can trust the prev ref root hash stored in it. We will use it to verify the next shard block proof until we find our wanted shard block
      console.log("prev block root hash: ", Buffer.from(block.info.prev_ref.prev.root_hash).toString("hex"));
      const validatedBlockHash = Buffer.from(block.info.prev_ref.prev.root_hash).toString("hex");
      validatedShardBlockHashes.push(validatedBlockHash);
    }
  }
  engine.close();
})();
