import TonRocks from "@oraichain/tonbridge-utils";
import { Block } from "@oraichain/tonbridge-utils/build/blockchain";
import { loadBlockExtra, loadTransaction } from "@oraichain/tonbridge-utils/build/blockchain/BlockParser";
import { Address as TonRocksAddress } from "@oraichain/tonbridge-utils/build/types";
import { Address, Cell } from "@ton/core";
import { assert } from "console";
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

// This file verifies if a transaction in a shard block. The shard block could be
(async () => {
  const { liteservers } = await fetch("https://ton.org/global.config.json").then((data) => data.json());
  // Personal choice. Can choose a different index if needed
  const server = liteservers[5];

  const engines: LiteEngine[] = [];
  engines.push(
    new LiteSingleEngine({
      host: `tcp://${intToIP(server.ip)}:${server.port}`,
      publicKey: Buffer.from(server.id.key, "base64")
    })
  );
  const engine: LiteEngine = new LiteRoundRobinEngine(engines);
  const client = new LiteClient({ engine });
  const addressRaw = "UQAQw3YLaG2HvvH1xaJehyAaJ--PX4gFxi70NwC1p_b4nISf";
  const result = await fetch(
    `https://toncenter.com/api/v3/transactions?account=${addressRaw}&limit=100&offset=0&sort=desc`
  ).then((data) => data.json());
  const { block_ref, mc_block_seqno, hash, lt } = result.transactions.find((tx) => {
    return (
      Buffer.from(tx.hash, "base64").toString("hex") ===
      "25d1ed22d37fa5ec44b4426f00f33ee3f59e527e8252b9da266172d342c0f5fd"
    );
  });
  console.log("mc block seqno: ", mc_block_seqno, block_ref);
  const fullBlock = await client.getFullBlock(mc_block_seqno);
  const mcBlockId = fullBlock.shards.find((shard) => shard.seqno === mc_block_seqno);
  const wantedShardInfo = fullBlock.shards.find((shard) => shard.seqno === block_ref.seqno);

  // PROVE that our shard block is valid via shard proofs.
  const blockProof = await engine.query(Functions.liteServer_getShardBlockProof, {
    kind: "liteServer.getShardBlockProof",
    id: {
      kind: "tonNode.blockIdExt",
      ...wantedShardInfo
    }
  });
  let validatedShardBlockHashes = [];
  for (let i = 0; i < blockProof.links.length; i++) {
    const link = blockProof.links[i];
    // the first link is the shard block that is included in the masterchain block.
    // Assume that we already verified the masterchain block via validator signatures
    //
    const blockProofCell = await TonRocks.types.Cell.fromBoc(link.proof);
    const block = TonRocks.bc.BlockParser.parseBlock(blockProofCell[0].refs[0]);
    console.log("block boc: ", Cell.fromBoc(link.proof));
    const blockRootHash = Buffer.from(blockProofCell[0].refs[0].getHash(0)).toString("hex");
    if (i === 0) {
      console.log("block root hash i === 0: ", blockRootHash, mcBlockId.rootHash.toString("hex"));
      // gotta make sure this proof is valid by checking if the block in the proof matches our trusted masterchain hash
      assert(mcBlockId.rootHash.toString("hex") === blockRootHash);
      // TODO: need to make sure on Rust this is a list of shardDescr because shard_hashes is a map
      const shardDescr = Block._shardGetFromHashmap(
        block.extra.custom.shard_hashes,
        wantedShardInfo.workchain,
        new TonRocksAddress(addressRaw).hashPart
      );
      validatedShardBlockHashes.push(Buffer.from(shardDescr.root_hash).toString("hex"));
    }
    if (i > 0) {
      console.log("block root hash i > 0: ", blockRootHash, validatedShardBlockHashes[i - 1]);
      // since the proofs are links from the wanted shard block to the masterchain block, hash of block_proof[i] must be in the validate shard block hashes
      assert(validatedShardBlockHashes.some((hash) => blockRootHash === hash));
      // since this block proof is validated, we can trust the prev ref root hash stored in it. We will use it to verify the next shard block proof until we find our wanted shard block
      const validatedBlockHash = Buffer.from(block.info.prev_ref.prev.root_hash).toString("hex");
      validatedShardBlockHashes.push(validatedBlockHash);
    }
    if (
      validatedShardBlockHashes.length > 0 &&
      validatedShardBlockHashes.some((hash) => hash === wantedShardInfo.rootHash.toString("hex"))
    ) {
      console.log("finished validating our shard block");
      break;
    }
  }
  // PROVE TX MATCHES THE TX WE EXPECT AND IT IS IN OUR VALIDATED SHARD BLOCK
  const transaction = await client.getAccountTransaction(Address.parse(addressRaw), lt, wantedShardInfo);
  const transactionProofCell = await TonRocks.types.Cell.fromBoc(transaction.proof);
  const transactionDetailCell = await TonRocks.types.Cell.fromBoc(transaction.transaction);
  const transactionDetail = loadTransaction(transactionDetailCell[0], { cs: 0, ref: 0 });
  // console.log("transaction detail: ", transactionDetail);
  const merkleProofHash = Buffer.from(transactionProofCell[0].refs[0].getHash(0)).toString("hex");
  // the transaction's block hash must match the shard block's hash
  assert(validatedShardBlockHashes.some((hash) => merkleProofHash === hash));
  const blockExtra = loadBlockExtra(transactionProofCell[0].refs[0].refs[3], { cs: 0, ref: 0 });
  const blockExtraMap = blockExtra.account_blocks.map;
  blockExtraMap.forEach(async (value, key) => {
    const txHash = Buffer.from(value.value.transactions.map.get(Number(lt).toString(16)).value.getHash(0)).toString(
      "hex"
    );
    assert(txHash === Buffer.from(transactionDetail.hash).toString("hex"));
  });

  engine.close();
})();
