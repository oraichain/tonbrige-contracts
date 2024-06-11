import { SimulateCosmWasmClient } from "@oraichain/cw-simulate";
import { toAmount } from "@oraichain/oraidex-common";
import { OraiswapTokenClient } from "@oraichain/oraidex-contracts-sdk";
import {
  InstantiateMsg as Cw20InstantiateMsg,
  MinterResponse
} from "@oraichain/oraidex-contracts-sdk/build/OraiswapToken.types";
import { deployContract } from "@oraichain/tonbridge-contracts-build";
import { TonbridgeBridgeClient, TonbridgeValidatorClient } from "@oraichain/tonbridge-contracts-sdk";
import { ValidatorSignature } from "@oraichain/tonbridge-utils";
import { Address } from "@ton/core";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions, liteServer_masterchainInfoExt } from "ton-lite-client/dist/schema";
import TonWeb from "tonweb";
import { intToIP } from "../src/common";
import { queryAllValidatorCandidates, queryAllValidators, queryKeyBlock } from "./common";

describe("Real Ton data tests", () => {
  const client = new SimulateCosmWasmClient({
    chainId: "Oraichain",
    bech32Prefix: "orai",
    metering: true
  });
  const sender = "orai12zyu8w93h0q2lcnt50g3fn0w3yqnhy4fvawaqz";
  let liteClient: LiteClient;
  let liteEngine: LiteEngine;
  let validator: TonbridgeValidatorClient;
  let bridge: TonbridgeBridgeClient;
  let dummyToken: OraiswapTokenClient;

  let masterchainInfo: liteServer_masterchainInfoExt;
  let initialVerifiedRootHash: string;
  let initialKeyBlockBoc: string = ""; // in hex form
  let initialKeyBlockSeqNo = 38125645; // the seqno of the boc hardcoded in @oraichain/tonbridge-utils/blockParserLarge.ts

  beforeAll(async function () {
    // setup lite engine server
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
    liteEngine = new LiteRoundRobinEngine(engines);
    liteClient = new LiteClient({ engine: liteEngine });

    masterchainInfo = await liteClient.getMasterchainInfoExt();
    const { rawBlockData, initialKeyBlockInformation } = await queryKeyBlock(
      liteClient,
      liteEngine,
      masterchainInfo.last.seqno
    );
    initialKeyBlockSeqNo = initialKeyBlockInformation.seqno;
    initialKeyBlockBoc = rawBlockData.data.toString("hex");
    initialVerifiedRootHash = rawBlockData.id.rootHash.toString("hex");

    // deploy contracts
    const validatorDeployResult = await deployContract(
      client,
      sender,
      { boc: initialKeyBlockBoc },
      "bridge-validator",
      "cw-tonbridge-validator"
    );
    const bridgeDeployResult = await deployContract(client, sender, {}, "bridge-bridge", "cw-tonbridge-bridge");
    const dummyTokenDeployResult = await deployContract(
      client,
      sender,
      {
        decimals: 6,
        initial_balances: [{ address: sender, amount: toAmount(10000).toString() }],
        name: "Dummy Token",
        symbol: "DUMMY",
        mint: {
          minter: bridgeDeployResult.contractAddress
        } as MinterResponse
      } as Cw20InstantiateMsg,
      "dummy-token",
      "oraiswap-token"
    );

    validator = new TonbridgeValidatorClient(client, sender, validatorDeployResult.contractAddress);
    bridge = new TonbridgeBridgeClient(client, sender, bridgeDeployResult.contractAddress);
    dummyToken = new OraiswapTokenClient(client, sender, dummyTokenDeployResult.contractAddress);

    // FIXME: change denom & channel id to correct denom and channel id
    await bridge.updateMappingPair({
      denom: "",
      localAssetInfo: { token: { contract_addr: dummyToken.contractAddress } },
      localChannelId: "",
      localAssetInfoDecimals: 6,
      remoteDecimals: 6
    });
  }, 100000);

  afterAll(() => {
    liteEngine.close();
  });

  it("after parse validator set contract the initital block should be verified", async () => {
    expect(await validator.isVerifiedBlock({ rootHash: initialVerifiedRootHash })).toEqual(true);
    let validators = (await queryAllValidators(validator))
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    console.log("validators length: ", validators.length);

    expect(validators.length).toEqual(343);
    validators = (await queryAllValidatorCandidates(validator)).filter((validator) => validator.c_type !== 0);
    expect(validators.length).toEqual(0);
  });

  it("Verify a block using validator signatures in new block real data", async () => {
    const blockToCheck = masterchainInfo.last.seqno;
    const fullBlock = await liteClient.getFullBlock(blockToCheck);
    const blockId = fullBlock.shards.find((blockRes) => blockRes.seqno === blockToCheck);
    const tonweb = new TonWeb();
    const valSignatures = (await tonweb.provider.send("getMasterchainBlockSignatures", {
      seqno: blockId.seqno
    })) as any;
    const signatures = valSignatures.signatures as ValidatorSignature[];
    const vdata = signatures.map((sig) => {
      const signatureBuffer = Buffer.from(sig.signature, "base64");
      const r = signatureBuffer.subarray(0, 32);
      const s = signatureBuffer.subarray(32);
      return {
        node_id: Buffer.from(sig.node_id_short, "base64").toString("hex"),
        r: r.toString("hex"),
        s: s.toString("hex")
      };
    });

    const blockHeader = await liteClient.getBlockHeader(blockId);
    const blockInfo = await liteEngine.query(Functions.liteServer_getBlock, {
      kind: "liteServer.getBlock",
      id: {
        kind: "tonNode.blockIdExt",
        ...blockId
      }
    });
    await validator.verifyMasterchainBlockByValidatorSignatures({
      blockHeaderProof: blockHeader.headerProof.toString("hex"),
      blockBoc: blockInfo.data.toString("hex"),
      fileHash: blockId.fileHash.toString("hex"),
      vdata
    });

    expect(await validator.isVerifiedBlock({ rootHash: blockId.rootHash.toString("hex") })).toEqual(true);

    // candidates now should be empty because we the list has been verified
    const validators = (await queryAllValidatorCandidates(validator)).filter((validator) => validator.c_type !== 0);
    expect(validators.length).toEqual(0);
  }, 15000);

  it("Verify updated validator signatures in new block real data", async () => {
    const blockToCheck = initialKeyBlockSeqNo - 1;
    const {
      parsedBlock,
      rawBlockData,
      initialKeyBlockInformation: blockId
    } = await queryKeyBlock(liteClient, liteEngine, blockToCheck);
    const boc = rawBlockData.data.toString("hex");

    await validator.prepareNewKeyBlock({ keyblockBoc: boc });

    const tonweb = new TonWeb();
    const valSignatures = (await tonweb.provider.send("getMasterchainBlockSignatures", {
      seqno: blockId.seqno
    })) as any;
    const signatures = valSignatures.signatures as ValidatorSignature[];
    const vdata = signatures.map((sig) => {
      const signatureBuffer = Buffer.from(sig.signature, "base64");
      const r = signatureBuffer.subarray(0, 32);
      const s = signatureBuffer.subarray(32);
      return {
        node_id: Buffer.from(sig.node_id_short, "base64").toString("hex"),
        r: r.toString("hex"),
        s: s.toString("hex")
      };
    });

    await validator.verifyKeyBlock({
      rootHash: rawBlockData.id.rootHash.toString("hex"),
      fileHash: rawBlockData.id.fileHash.toString("hex"),
      vdata
    });

    for (let i = 0; i < signatures.length; i++) {
      expect(
        await validator.isSignedByValidator({
          validatorNodeId: vdata[i].node_id,
          rootHash: rawBlockData.id.rootHash.toString("hex")
        })
      ).toEqual(true);
    }
    expect(await validator.isVerifiedBlock({ rootHash: rawBlockData.id.rootHash.toString("hex") })).toEqual(true);

    let validators = (await queryAllValidators(validator)).filter((validator) => validator.c_type !== 0);
    expect(validators.length).toBeGreaterThan(1000);

    // candidates now should be empty because we the list has been verified
    validators = (await queryAllValidatorCandidates(validator)).filter((validator) => validator.c_type !== 0);

    expect(validators.length).toEqual(0);
  }, 15000);

  it("shard block test real data", async () => {
    const shardInfo = await liteClient.lookupBlockByID({ seqno: 43884169, shard: "2000000000000000", workchain: 0 });
    const shardProof = await liteEngine.query(Functions.liteServer_getShardBlockProof, {
      kind: "liteServer.getShardBlockProof",
      id: {
        kind: "tonNode.blockIdExt",
        ...shardInfo.id
      }
    });
    const mcBlockRootHash = shardProof.masterchainId.rootHash.toString("hex");
    // assume that the masterchain block is already verified by validator signatures
    await validator.setVerifiedBlock({ rootHash: mcBlockRootHash, seqNo: shardProof.masterchainId.seqno });
    await validator.verifyShardBlocks({
      mcBlockRootHash: mcBlockRootHash,
      shardProofLinks: shardProof.links.map((link) => link.proof.toString("hex"))
    });

    // root hashes parsed from the proof links above. To know how to parse them, see https://github.com/oraichain/tonbridge-evm-contracts/tree/develop/rust-contracts-sdk/packages/contracts-demo/src/verify-shard-blocks-via-proof-link.ts
    expect(
      await validator.isVerifiedBlock({ rootHash: "5d5215c4dd5e2dc3e8b0640339303135cd7296c577e37d1f0e1781cde6fb9629" })
    ).toEqual(true);
    expect(
      await validator.isVerifiedBlock({ rootHash: "0299328dbd84b0ece362aec8cb04f89f7f21b1908dd55542ae9983914d81b7d1" })
    ).toEqual(true);
  }, 20000);

  it("bridge contract reads real data from masterchain block's transaction", async () => {
    // check if our wanted shard blocks have been verified or not. If not then we verify them
    const isVerified = await validator.isVerifiedBlock({
      rootHash: "0299328dbd84b0ece362aec8cb04f89f7f21b1908dd55542ae9983914d81b7d1"
    });
    // verify necessary masterchain and shard blocks so that we can verify our tx
    if (!isVerified) {
      const shardInfo = await liteClient.lookupBlockByID({ seqno: 43884169, shard: "2000000000000000", workchain: 0 });
      const shardProof = await liteEngine.query(Functions.liteServer_getShardBlockProof, {
        kind: "liteServer.getShardBlockProof",
        id: {
          kind: "tonNode.blockIdExt",
          ...shardInfo.id
        }
      });
      const mcBlockRootHash = shardProof.masterchainId.rootHash.toString("hex");
      // assume that the masterchain block is already verified by validator signatures
      await validator.setVerifiedBlock({ rootHash: mcBlockRootHash, seqNo: shardProof.masterchainId.seqno });
      await validator.verifyShardBlocks({
        mcBlockRootHash: mcBlockRootHash,
        shardProofLinks: shardProof.links.map((link) => link.proof.toString("hex"))
      });
    }
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
    const shardInfo = await liteClient.lookupBlockByID(block_ref);
    // PROVE TX MATCHES THE TX WE EXPECT AND IT IS IN OUR VALIDATED SHARD BLOCK
    const transaction = await liteClient.getAccountTransaction(Address.parse(addressRaw), lt, shardInfo.id);
    await bridge.readTransaction({
      txBoc: transaction.transaction.toString("hex"),
      txProof: transaction.proof.toString("hex"),
      validatorContractAddr: validator.contractAddress,
      opcode: "0000000000000000000000000000000000000000000000000000000000000001"
    });
  }, 100000);
});
