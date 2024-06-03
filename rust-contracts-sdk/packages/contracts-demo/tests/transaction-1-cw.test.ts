import { SimulateCosmWasmClient } from "@oraichain/cw-simulate";
import { toAmount } from "@oraichain/oraidex-common";
import { OraiswapTokenClient } from "@oraichain/oraidex-contracts-sdk";
import {
  InstantiateMsg as Cw20InstantiateMsg,
  MinterResponse
} from "@oraichain/oraidex-contracts-sdk/build/OraiswapToken.types";
import {
  data,
  findBoc,
  findTxHash,
  initialValidatorsBlockRootHash,
  initialValidatorsList,
  updateValidators,
  updateValidatorsRootHash
} from "../../../../test/data/transaction-1";
import { deployContract } from "../../contracts-build/src";
import { TonbridgeBridgeClient, TonbridgeValidatorClient } from "../../contracts-sdk/src";
import { Amount } from "../../contracts-sdk/src/TonbridgeBridge.types";
import { Cell } from "@ton/core";

describe("Tree of Cells parser tests 1", () => {
  const client = new SimulateCosmWasmClient({
    chainId: "Oraichain",
    bech32Prefix: "orai"
  });
  const sender = "orai12zyu8w93h0q2lcnt50g3fn0w3yqnhy4fvawaqz";
  let validator: TonbridgeValidatorClient;
  let bridge: TonbridgeBridgeClient;
  let dummyToken: OraiswapTokenClient;

  beforeAll(async function () {
    // deploy contracts
    const validatorDeployResult = await deployContract(
      client,
      sender,
      { boc: findBoc("set-validators").toString("hex") },
      "bridge-validator",
      "cw-tonbridge-validator"
    );
    const cells = Cell.fromBoc(findBoc("set-validators"));
    const firstCell = Uint8Array.from(cells[0].hash(0));
    console.log("first cell hash: ", firstCell);
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

  it("Should throw an error when use wrong boc for parseCandidatesRootBlock", async () => {
    const boc = findBoc("state-hash");
    try {
      await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });
      expect(false);
    } catch (error) {
      expect(true);
    }
  });

  it("after init contract the initital block should be verified", async () => {
    expect(await validator.isVerifiedBlock({ rootHash: initialValidatorsBlockRootHash })).toEqual(true);
    let validators = (await validator.getValidators())
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    validators.forEach((validator) => {
      const item = initialValidatorsList.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });

    validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);
    expect(validators.length).toEqual(0);
  });

  it("Verify updated validator signatures in new block", async () => {
    const boc = findBoc("proof-validators");
    await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });

    let validators = (await validator.getCandidatesForValidators())
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    expect(validators.length).toEqual(14);

    validators.forEach((validator) => {
      const item = updateValidators.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });

    const signatures = data.find((el) => el.type === "proof-validators")!.signatures!;

    await validator.verifyValidators({
      rootHash: "0000000000000000000000000000000000000000000000000000000000000000",
      fileHash: data.find((el) => el.type === "proof-validators")!.id!.fileHash,
      vdata: signatures
    });

    for (let i = 0; i < signatures.length; i++) {
      expect(
        await validator.isSignedByValidator({
          validatorNodeId: signatures[i].node_id,
          rootHash: updateValidatorsRootHash
        })
      ).toEqual(true);
    }
    expect(await validator.isVerifiedBlock({ rootHash: updateValidatorsRootHash })).toEqual(true);

    validators = (await validator.getValidators())
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    validators.forEach((validator) => {
      const item = updateValidators.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });

    // candidates now should be empty because we the list has been verified
    validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);

    expect(validators.length).toEqual(0);
  });

  it("keyblock test", async () => {
    // fixture. Setting up a new verified block
    // Normally, this should be verified using validator signatures.
    const masterBlockRootHash = "456ae983e2af89959179ed8b0e47ab702f06addef7022cb6c365aac4b0e5a0b9";
    const stateHashBoc = findBoc("state-hash").toString("hex");
    await validator.setVerifiedBlock({
      rootHash: masterBlockRootHash,
      seqNo: 0
    });
    expect(
      await validator.isVerifiedBlock({
        rootHash: masterBlockRootHash
      })
    ).toEqual(true);

    // Store state hash of the block so that we can use it to validate older blocks
    await validator.readMasterProof({ boc: stateHashBoc });

    // testing. Validate an older block on the masterchain
    const shardStateBoc = findBoc("shard-state").toString("hex");
    await validator.readStateProof({
      boc: shardStateBoc,
      rootHash: masterBlockRootHash
    });

    expect(
      await validator.isVerifiedBlock({
        // root block hash of the older block compared to the master block
        rootHash: "ef2b87352875737c44346b7588cb799b6ca7c10e47015515026f035fe8b6a5c7"
      })
    ).toEqual(true);
  });

  it("shard block test", async () => {
    // Prerequisite: need the new masterchain's block to be verified first
    const masterBlockRootHash = "456ae983e2af89959179ed8b0e47ab702f06addef7022cb6c365aac4b0e5a0b9";
    expect(
      await validator.isVerifiedBlock({
        rootHash: masterBlockRootHash
      })
    ).toEqual(true);
    const boc = findBoc("shard-block").toString("hex");

    await validator.parseShardProofPath({ boc });
    expect(
      await validator.isVerifiedBlock({
        // root hash of the shard block
        rootHash: "641ccceabf2d7944f87e7c7d0e5de8c5e00b890044cc6d21ce14103becc6196a"
      })
    ).toEqual(true);
  });

  it("bridge contract reads data from transaction", async () => {
    const blockBoc = findBoc("tx-proof").toString("hex");
    const txBoc = findBoc("tx-proof", true).toString("hex");

    await bridge.readTransaction({
      txBoc,
      blockBoc,
      validatorContractAddr: validator.contractAddress,
      opcode: "0000000000000000000000000000000000000000000000000000000000000001"
    });

    // FIXME: this address is converted from 20 bytes of the address in the tx boc.
    const balanceOf = await dummyToken.balance({ address: "orai1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqskuxw" });
    // FIXME: balance = 1 because we hard-coded it in the contract for testing. Should not be 1 in real tests
    expect(balanceOf.balance).toEqual("1");

    const channelBalance = await bridge.channelStateData({ channelId: "" });
    expect(channelBalance.balances.length).toEqual(1);
    expect(channelBalance.balances[0]).toEqual({ native: { amount: "1", denom: "" } } as Amount);
    expect(channelBalance.total_sent.length).toEqual(1);
    expect(channelBalance.total_sent[0]).toEqual({ native: { amount: "1", denom: "" } } as Amount);

    const txHash = findTxHash();
    const isTxProcessed = await bridge.isTxProcessed({
      txHash
    });
    expect(isTxProcessed).toEqual(true);
  });
});
