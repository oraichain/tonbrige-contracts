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
    const initKeyBlockSeqno = 38103071;
    const fullBlock = await liteClient.getFullBlock(initKeyBlockSeqno);
    const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
    // console.log(initialKeyBlockInformation);
    const blockConfig = await liteClient.getConfig(initialKeyBlockInformation);
    // const validatorSetCell = blockConfig.config.get(34);
    const block = await liteEngine.query(Functions.liteServer_getBlock, {
      kind: "liteServer.getBlock",
      id: {
        kind: "tonNode.blockIdExt",
        ...initialKeyBlockInformation
      }
    });
    await validator.parseCandidatesRootBlock({
      // got from parsedBlockData[0] in validator-set
      boc: "b5ee9c7241025601000bca00041011ef55aaffffff110103040501a09bc7a9870000000006010245681f0000000100ffffffff000000000000000066554f0800002a874693254000002a8746932544a102605e0008ae330245681b02456195c400000007000000000000002e02084801019b6c7fc533377647d645f4f5b578ee9906c259bf7b95bbc0378a5bcfd7bc8d4900000848010183bee4634100c7df82e5e759ea3c9470c98e480c28e25d6b8c54f162e3b14bb2000308480101b0a11d82599ade4b6379bbe49cd61d53f27c93d3aa7ca240d6486c0f5249dca3001904894a33f6fdc0000a8d203bed2d33fa0347c1d8f9233276931073bdbf8b9d6f5d6f6d03f3ad4dfa6cf97c88292bf957e51b7f47c00b8adff6791ed0bc8e25216d265c3c8be0c00607080908480101fbe9a1cf62c47860aa0cdb6a4aa92b0f4ea4c469e5bd5a96e401db135ec57f70000408480101ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc00000848010164ee540cdac8f85ded8c5f11962590e03f7eeb323ab3bd99799cf29d20144eb300060457cca5e84675234441dcd65002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac0a0b0c0d0848010101e66bcdc6fb5662ec69f01f08cd8782116ef89ba5b66991d0e3188a7094cbff000308480101c9d0ce19f8bdf1ab1c1c21cbf3b5d0f1f9629abdd038b1e3225adfbb632c25be0000084801013e3a5ae5d392b52bd32ce65f9d6e9560877547a2909ea1689fafaa4b2881f97900040201200e550202d80f54020120101108480101de70a0f05da88854f9fe176d5b52feb30c491be25db8d0de21aa9a1678ee7c14000d02014812530201481314084801010c4731ee64fd6fc7fc50c61b2ba5be68801ca478d0551748d2e9fc7830b2bc63000b01014815012b1266554f0866564f08015500640fffffffffffff51c0160202c71726020120181f020120191c0201201a1b28480101fc3819ff0e0be9ba112487fa4d76c13a71777032b810045695ef2983e0f5c555000528480101487d0998be3abee0e57b7b8ebbf68dc311cc7a59001183bc903b854606e0b5cb00050201201d1e2848010147c73d9e2f3893eb23af93760b7fbc83a89381675ca489cfe53cb09abedadb0a000528480101bae5f3cfb3904826d1303dc867e2ae42a24dd322b1953812ad28b91d79185a9400050201202023020120212228480101e3914911a1190b136ade52dac8aad408c5df3548af88d674dba0ef2c4c5812700005284801011eee71a5f678ebbbcb5d5e25b3eb9d2217a785a3f23592506d626bfae9be7e24000502012024252848010128dc01810cf281d7410bbcda6f26d1a0ce110d8133207f85859ce084d3d2f70600052848010144c22d852f0dd5b630d187a48e9f80b8479999e6f966f5f0226f935af2e18dcf0005020148272a0201202829284801011eb79e60bc4e47d668939b9875bfb18e979dcfb898821df38e50f65c157b78a000052848010190dd3a158c7d9dde2c4bb63c139969515cb2c7e7b78c18dc3d26f5ca46305a5700050201482b4a0201202c3b0201202d340201202e310201202f30009b1ce3a049e28d99c8d2228004c33371269579617c0fcf697516ae738c7557777a36f2de869ac0019972520a8b2bfe969ee37b1464abeb36f8506017832640fde9d48dd0821bcabf4a9906d1d41f60009b1ce3a049e2a941708279ee5274c4abf605dddedf32eccac909dcd6820278f38fab0e0d95470001997252088d5af93e9d341942e06c620175adc4b221f9e2163929c105b65517f37226cde7574b600201203233009b1ce3a049e29b6880057d1238a22a873f0ab8cb2ee91c6538710a4f236132cc27d9a47afe30800199725200bc7ff2c8b1a26460d7e7eae52dfe40909c51d7e7eea418e138215ba3d4c0e8c20b1d20009b1ce3a049e295030114be129fd5715fbfb95e8613214bf0c142cca1cc05bc3f4e1227423c3d400197aaa583719c99b766e1097b0c697a31c6b9830430d7fc43df7997f8489b32dbaba8289f509c2002012035380201203637009b1ce3a049e2bee5c4ddf77f558e17789ed05b468fa49f33880ba0722a768b0bebddd5d61121c001915e657ebf96774e239a8aaaaa6825e50b02c3c50fa16c5f3a51731e251456a07a98a8cc1068a0009b1ce3a049e2bf8cdd743d04fb696f5a99b370675046dab7555fd3cffab8362395f9be2c4cb880018de69cd39515d3764f229d1c88c22b06ef075e21b1c8f0c771b6c8e33adddb5110b9a8c65666e0020120393a009b1ce3a049e2b82d242c9e6f55e840813bfb5da13842b3fcf129bda699dd02b0d61beec391f180018a7e77b95bde16bc1a0542b99e66bc96d10bb9ffcc4e3444680d605705eaa6ace9586192e61b20009b1ce3a049e28055e4a0a3dc58d27f4cfc41051715ec2f284737ef3fe618789ab4011a257937800189b69daad413347a48d732171be469bf62d0bd3abf3bd5632f28a017c6499d142dbff7cbb77b200201203c430201203d400201203e3f009b1ce3a049e2bda5e528e3aaf277e58a71bfa9604f855992c4928378f16d51118178aadf7cc6000187bcfa01dfda211a0c30232cce3aa5ee07fbd687dd141357211e438e2ca7dcd9ff71e6b77d2ee0009b1ce3a049e2934bbf7584480f8eb56c5070d40c5e6ef09591f10fa7728a73ea6541973dfbea800187bcf9f7e562c15395a1696ff44df6738a05f4758e5bd6204038ffda099966835afc24e1a6b7e00201204142009b1ce3a049e28d71d4d3675f338cc787178582c7d2a464450c8e8b95d6761f0de0c9559793ae400185c7dddf019332a4ac98a2efd72e21836c998b86f9d3878cf6faf1d1316176b6150d971cad9de0009b1ce3a049e2bb9a12e968c7e271786b64403f915056cd0d181885a55230d02da3b0b0daf510800179a54d9cfe61c50325d066d51cbedfcfe7b97c384f4371bd1c098194dac5151cd17421d431c1e002012044470201204546009b1ce3a049e2bba182f1c98008d1405878e9ac5998002b2a8a1023ac27013aa055606344c294c00179a54d9cfe61ce975cb4348ab30e410ba138f8086d3de422ac547982347aee7550421a8e272ea0009b1ce3a049e29484ad3ac9487eac7fe9106649baf5c30570672a4c275dc7d3a7de65a8b2b94f80016a71837b2d16af7222a228ac5c6afc0ce82e4f2b06c03fcc2ccc11f18f74102de79e527e3db3200201204849009b1ce3a049e2a756596a0408f9879f80fc71cccb927ddc49f9cb1bf13c8ccb82cae03e85652540016848758d9d1ec9f23d6d08ccec0c34510a36ae538f0bec3bc36b69b6d2e8632196c252e5431ae0009b1ce3a049e2b3b031f124d810f231319eb72d8b3c9f60eedea231947273e9c2839e4fac6931400167baa5ef5050dffb7a25e6464149904f9053db2e36c2abe27fac4e790f5450ad39148babee88600201484b520201204c4f0201204d4e009b1ce3a049e28ded120d032b1f0ccdd652ff5cc4edc468c81b9299a98499d7702ef95b57bb2440016359006559986c45b84437332d4213c465856e6069edb1e18f2f07711f8446b06b6d9ca4f97aa0009b1ce3a049e29b32046ccc1b7b852a79b1d5ddbcb48a1654ddc8690fca4312f55560e647ffc18001623415c5408446d31d2170d3bb67765785fe00cab6380beb648993790c6b62f6d6f9aa8653d6600201205051009b1ce3a049e29779d5d9510868cea6b3c4248e42c46f3cb6c3533786379991e3c8c3ab6cfd5e80015c49f40f6c1c835769594bb5b3155002c489cb502d4f04440a69ccee796ce840fea2d50fcc36a0009b1ce3a049e2b2c21f97a7f3e9d1a319a7daa2781e81b24410ec3125dd7c4410402ff489b2d540015746531a25186209050cb8486130a3009ee61a9863f073006859aa23d66609809ffc79d22f3f20009bd39c74093c52850ea93f9cda982df2ddc761f0cfa219889812a53e49b25f00c99a6618242940002a4fbcd14e7942b49bd477f3b49a88bdbc213fa4904a1d192a711a752d6afd39c075af99a1c8ac084801012c60df2ad5c564c1a5717b0396ed695c0eb00c33130a12736650261f7cd3ec15000e08480101112a0556a091dc4f72bd31ff2790783fb3238ce2aa41e1c137424d279664d7e3000a0848010124d21cf7ae96b1c55a1230e823db0317ce24ec33e3bf2585c79605684304faf200075217bd00"
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
