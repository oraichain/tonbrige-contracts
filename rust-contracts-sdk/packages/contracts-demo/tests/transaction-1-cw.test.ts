import { SimulateCosmWasmClient } from "@oraichain/cw-simulate";
import {
  data,
  findBoc,
  initialValidatorsBlockRootHash,
  initialValidatorsList,
  updateValidators,
  updateValidatorsRootHash
} from "../../../../test/data/transaction-1";
import { deployContract } from "../../contracts-build/src";
import { TonbridgeBridgeClient, TonbridgeValidatorClient } from "../../contracts-sdk/src";

describe("Tree of Cells parser tests 1", () => {
  const client = new SimulateCosmWasmClient({
    chainId: "Oraichain",
    bech32Prefix: "orai"
  });
  const sender = "orai12zyu8w93h0q2lcnt50g3fn0w3yqnhy4fvawaqz";
  let validator: TonbridgeValidatorClient;
  let bridge: TonbridgeBridgeClient;

  beforeAll(async function () {
    // deploy contracts
    const validatorDeployResult = await deployContract(
      client,
      sender,
      { boc: findBoc("set-validators").toString("hex") },
      "bridge-validator",
      "cw-tonbridge-validator"
    );
    const bridgeDeployResult = await deployContract(client, sender, {}, "bridge-bridge", "cw-tonbridge-bridge");

    validator = new TonbridgeValidatorClient(client, sender, validatorDeployResult.contractAddress);
    bridge = new TonbridgeBridgeClient(client, sender, bridgeDeployResult.contractAddress);
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

  it("Should change to a new set of validators from boc to candidatesForValidators", async () => {
    const boc = findBoc("proof-validators");

    await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });

    const validators = (await validator.getCandidatesForValidators())
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    expect(validators.length).toEqual(14);

    validators.forEach((validator) => {
      const item = updateValidators.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });
  });

  it("Should set updated validator set and its block's hash", async () => {
    const boc = findBoc("proof-validators");
    await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });
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

    let validators = (await validator.getValidators())
      .filter((validator) => validator.c_type !== 0)
      .map((validator) => ({ ...validator, node_id: "0x" + validator.node_id, pubkey: "0x" + validator.pubkey }));

    expect(await validator.isVerifiedBlock({ rootHash: updateValidatorsRootHash })).toEqual(true);

    validators.forEach((validator) => {
      const item = updateValidators.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });

    validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);

    expect(validators.length).toEqual(0);
  });

  it("Should add validators for update from boc to candidatesForValidators", async () => {});

  it("Should throw an exception for set validators when signatures was not checked", async () => {});

  // TODO: check signatures for wrong boc/fileHash/vdata
  it("Should verify signatures", async () => {});

  it("should update validators", async () => {});

  it("verify-signature test", async () => {});

  it("shard state test", async () => {});

  it("shard block test", async () => {});

  it("bridge contract reads data from transaction", async () => {});
});
