import { SimulateCosmWasmClient } from "@oraichain/cw-simulate";
import { toAmount } from "@oraichain/oraidex-common";
import { OraiswapTokenClient } from "@oraichain/oraidex-contracts-sdk";
import {
  InstantiateMsg as Cw20InstantiateMsg,
  MinterResponse
} from "@oraichain/oraidex-contracts-sdk/build/OraiswapToken.types";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions, liteServer_masterchainInfoExt } from "ton-lite-client/dist/schema";
// import { initialValidatorsBlockRootHash, initialValidatorsList } from "../../../../test/data/transaction-1";
import { deployContract } from "../../contracts-build/src";
import { TonbridgeBridgeClient, TonbridgeValidatorClient } from "../../contracts-sdk/src";
import { intToIP } from "../src/common";

describe("Real Ton data tests", () => {
  const client = new SimulateCosmWasmClient({
    chainId: "Oraichain",
    bech32Prefix: "orai"
  });
  const sender = "orai12zyu8w93h0q2lcnt50g3fn0w3yqnhy4fvawaqz";
  let liteClient: LiteClient;
  let liteEngine: LiteEngine;
  let validator: TonbridgeValidatorClient;
  let bridge: TonbridgeBridgeClient;
  let dummyToken: OraiswapTokenClient;

  let masterchainInfo: liteServer_masterchainInfoExt;

  beforeAll(async function () {
    // setup lite engine server
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
    liteEngine = new LiteRoundRobinEngine(engines);
    liteClient = new LiteClient({ engine: liteEngine });

    masterchainInfo = await liteClient.getMasterchainInfoExt();

    // deploy contracts
    const validatorDeployResult = await deployContract(
      client,
      sender,
      {},
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
  });

  afterAll(() => {
    liteEngine.close();
  });

  it("parse validator set", async () => {
    // const initKeyBlockSeqno = masterchainInfo.last.seqno;
    const initKeyBlockSeqno = 38098879;
    const fullBlock = await liteClient.getFullBlock(initKeyBlockSeqno);
    const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
    // console.log(initialKeyBlockInformation);
    const blockConfig = await liteClient.getConfig(initialKeyBlockInformation);
    const validatorSetCell = blockConfig.config.get(34);
    const configAll = await liteEngine.query(Functions.liteServer_getConfigAll, {
      kind: "liteServer.getConfigAll",
      id: {
        kind: "tonNode.blockIdExt",
        ...initialKeyBlockInformation
      },
      mode: 0
    });
    const block = await liteEngine.query(Functions.liteServer_getBlock, {
      kind: "liteServer.getBlock",
      id: {
        kind: "tonNode.blockIdExt",
        ...initialKeyBlockInformation
      }
    });
    await validator.parseCandidatesRootBlock({
      boc: "b5ee9c72410211010002c400245b9023afe2ffffff1100ffffffff0000000000000000024561110000000166552c3600002a86d37a6c840245610d600102030628480101816c59e169d6f97bb5d3325b03064ed0270807b6b38878dc0b0bea09d8c63a43000128480101a33a806b68d3bd5a0780e903ceb7988b882f7079e79c64465b89e3072ab7e163016e22330000000000000000ffffffffffffffff81ae56322a9211bc8828040528480101a5a7d24057d8643b2527709d986cda3846adcb3eddc32d28ec21f69e17dbaaef0001284801015f35cbccf98a08d1ffcac82eec82adb25708f4626a66d7a104b3b11f7d06e24b001c2455cc26aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac237270be1d589957e070c0d102103d040082201c0090b01db5014dc1a50122b0888000154369adf4000000154369adf41936f1ab02f1d70000acae8502cc2ae16ae8bbf2d1d44ff78098344a733bab69d69cd1086e4dd73d014610282a035c10f577cb73557e42f8640eb3bfccd290f8d80000045975a0000000000000000122b087332a9616a0a00134554baa7320ee6b2802028480101fe7094f87641ddb94015e0e688d26800776b12e7dd66de88bf8dcaa54aeff185000128480101f4cd53fd725a4ac1c42b9daa608a1f0db75d3cb77bc66e6d98a896177091ea57001222bf0001059684a10008ae0e60000550da6d6548880001541fe26994201229e69fe989cece59fc03bb6855380b5245562a9ff0681952f28f7fd1bf283c68bdab50e3d383552cebd8ceecc34c0fdfcceb170a98c01b8ae0d18d0d8e934afde4c218be0e0f284801015eba695305e40c9950bd2c388949ebf2f26e5542d09a3917f846fca743598df0001a2848010150d2d53bb7f07fc21d8dac28ae6982c72d9acb1a8877c67b0dcd0627f115600d001128480101b20e36a3b36a4cdee601106c642e90718b0a58daf200753dbb3189f956b494b6000147655e42"
    });
  }, 500000);

  // it("after parse validator set contract the initital block should be verified", async () => {
  //   expect(await validator.isVerifiedBlock({ rootHash: masterchainInfo.stateRootHash.toString("hex") })).toEqual(true);
  //   let validators = (await validator.getValidators())
  //     .filter((validator) => validator.c_type !== 0)
  //     .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

  //   console.log("validators: ", validator);

  //   // validators.forEach((validator) => {
  //   //   const item = initialValidatorsList.find((v) => v.node_id === validator.node_id);
  //   //   expect(item).not.toBeUndefined();
  //   //   expect(validator.pubkey).toEqual(item?.pubkey);
  //   // });

  //   validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);
  //   expect(validators.length).toEqual(0);
  // });

  // it("Verify updated validator signatures in new block", async () => {
  //   const boc = findBoc("proof-validators");
  //   await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });

  //   let validators = (await validator.getCandidatesForValidators())
  //     .filter((validator) => validator.c_type !== 0)
  //     .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

  //   expect(validators.length).toEqual(14);

  //   validators.forEach((validator) => {
  //     const item = updateValidators.find((v) => v.node_id === validator.node_id);
  //     expect(item).not.toBeUndefined();
  //     expect(validator.pubkey).toEqual(item?.pubkey);
  //   });

  //   const signatures = data.find((el) => el.type === "proof-validators")!.signatures!;

  //   await validator.verifyValidators({
  //     rootHash: "0000000000000000000000000000000000000000000000000000000000000000",
  //     fileHash: data.find((el) => el.type === "proof-validators")!.id!.fileHash,
  //     vdata: signatures
  //   });

  //   for (let i = 0; i < signatures.length; i++) {
  //     expect(
  //       await validator.isSignedByValidator({
  //         validatorNodeId: signatures[i].node_id,
  //         rootHash: updateValidatorsRootHash
  //       })
  //     ).toEqual(true);
  //   }
  //   expect(await validator.isVerifiedBlock({ rootHash: updateValidatorsRootHash })).toEqual(true);

  //   validators = (await validator.getValidators())
  //     .filter((validator) => validator.c_type !== 0)
  //     .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

  //   validators.forEach((validator) => {
  //     const item = updateValidators.find((v) => v.node_id === validator.node_id);
  //     expect(item).not.toBeUndefined();
  //     expect(validator.pubkey).toEqual(item?.pubkey);
  //   });

  //   // candidates now should be empty because we the list has been verified
  //   validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);

  //   expect(validators.length).toEqual(0);
  // });

  // it("keyblock test", async () => {
  //   // fixture. Setting up a new verified block
  //   // Normally, this should be verified using validator signatures.
  //   const masterBlockRootHash = "456ae983e2af89959179ed8b0e47ab702f06addef7022cb6c365aac4b0e5a0b9";
  //   const stateHashBoc = findBoc("state-hash").toString("hex");
  //   await validator.setVerifiedBlock({
  //     rootHash: masterBlockRootHash,
  //     seqNo: 0
  //   });
  //   expect(
  //     await validator.isVerifiedBlock({
  //       rootHash: masterBlockRootHash
  //     })
  //   ).toEqual(true);

  //   // Store state hash of the block so that we can use it to validate older blocks
  //   await validator.readMasterProof({ boc: stateHashBoc });

  //   // testing. Validate an older block on the masterchain
  //   const shardStateBoc = findBoc("shard-state").toString("hex");
  //   await validator.readStateProof({
  //     boc: shardStateBoc,
  //     rootHash: masterBlockRootHash
  //   });

  //   expect(
  //     await validator.isVerifiedBlock({
  //       // root block hash of the older block compared to the master block
  //       rootHash: "ef2b87352875737c44346b7588cb799b6ca7c10e47015515026f035fe8b6a5c7"
  //     })
  //   ).toEqual(true);
  // });

  // it("shard block test", async () => {
  //   // Prerequisite: need the new masterchain's block to be verified first
  //   const masterBlockRootHash = "456ae983e2af89959179ed8b0e47ab702f06addef7022cb6c365aac4b0e5a0b9";
  //   expect(
  //     await validator.isVerifiedBlock({
  //       rootHash: masterBlockRootHash
  //     })
  //   ).toEqual(true);
  //   const boc = findBoc("shard-block").toString("hex");

  //   await validator.parseShardProofPath({ boc });
  //   expect(
  //     await validator.isVerifiedBlock({
  //       // root hash of the shard block
  //       rootHash: "641ccceabf2d7944f87e7c7d0e5de8c5e00b890044cc6d21ce14103becc6196a"
  //     })
  //   ).toEqual(true);
  // });

  // it("bridge contract reads data from transaction", async () => {
  //   const blockBoc = findBoc("tx-proof").toString("hex");
  //   const txBoc = findBoc("tx-proof", true).toString("hex");

  //   await bridge.readTransaction({
  //     txBoc,
  //     blockBoc,
  //     validatorContractAddr: validator.contractAddress,
  //     opcode: "0000000000000000000000000000000000000000000000000000000000000001"
  //   });

  //   // FIXME: this address is converted from 20 bytes of the address in the tx boc.
  //   const balanceOf = await dummyToken.balance({ address: "orai1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqskuxw" });
  //   // FIXME: balance = 1 because we hard-coded it in the contract for testing. Should not be 1 in real tests
  //   expect(balanceOf.balance).toEqual("1");

  //   const channelBalance = await bridge.channelStateData({ channelId: "" });
  //   expect(channelBalance.balances.length).toEqual(1);
  //   expect(channelBalance.balances[0]).toEqual({ native: { amount: "1", denom: "" } } as Amount);
  //   expect(channelBalance.total_sent.length).toEqual(1);
  //   expect(channelBalance.total_sent[0]).toEqual({ native: { amount: "1", denom: "" } } as Amount);

  //   const txHash = findTxHash();
  //   const isTxProcessed = await bridge.isTxProcessed({
  //     txHash
  //   });
  //   expect(isTxProcessed).toEqual(true);
  // });
});
