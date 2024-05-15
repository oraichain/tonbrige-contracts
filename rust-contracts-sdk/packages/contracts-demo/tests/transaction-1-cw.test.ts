import { SimulateCosmWasmClient } from "@oraichain/cw-simulate";
import { findBoc, initialValidatorsList } from "../../../../test/data/transaction-1";
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
      {},
      "bridge-validator",
      "cw-tonbridge-validator"
    );
    const bridgeDeployResult = await deployContract(client, sender, {}, "bridge-bridge", "cw-tonbridge-bridge");

    validator = new TonbridgeValidatorClient(client, sender, validatorDeployResult.contractAddress);
    bridge = new TonbridgeBridgeClient(client, sender, bridgeDeployResult.contractAddress);

    // init validators to set default values
    await validator.initValidators();
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

  it("Should add validators from boc to candidatesForValidators", async () => {
    const boc = findBoc("set-validators");

    const res = await validator.parseCandidatesRootBlock({ boc: boc.toString("hex") });
    console.log(res);

    const validators = (await validator.getCandidatesForValidators()).filter((validator) => validator.c_type !== 0);
    console.log("validators: ", validators)

    validators.forEach((validator) => {
      const item = initialValidatorsList.find((v) => v.node_id === validator.node_id);
      expect(item).not.toBeUndefined();
      expect(validator.pubkey).toEqual(item?.pubkey);
    });
  });

  // TODO: onlyOwner test

  it("Should set initial validators and its block's hash", async () => {});

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
