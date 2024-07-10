use std::str::FromStr;

use cosmwasm_std::{
    attr, coin,
    testing::{mock_dependencies, mock_env, mock_info},
    to_binary, Addr, CosmosMsg, HexBinary, SubMsg, Timestamp, Uint128, WasmMsg,
};

use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20ReceiveMsg};
use cw20_ics20_msg::amount::Amount;
use cw_multi_test::Executor;

use oraiswap::{asset::AssetInfo, router::RouterController};
use tonbridge_bridge::{
    msg::{
        BridgeToTonMsg, ChannelResponse, ExecuteMsg, InstantiateMsg, QueryMsg as BridgeQueryMsg,
        UpdatePairMsg,
    },
    parser::build_commitment_key,
    state::{Config, MappingMetadata, Ratio, TokenFee},
};
use tonbridge_parser::{types::BridgePacketData, OPCODE_2};
use tonlib::{
    address::TonAddress,
    responses::{AnyCell, MaybeRefData, MessageType, TransactionMessage},
};

use crate::{
    bridge::{Bridge, DEFAULT_TIMEOUT},
    channel::increase_channel_balance,
    contract::{execute, instantiate},
    error::ContractError,
    helper::build_ack_commitment,
    state::{ACK_COMMITMENT, CONFIG, TOKEN_FEE},
    testing::mock::{new_mock_app, MockApp},
};

#[test]
fn test_validate_transaction_out_msg() {
    let mut maybe_ref = MaybeRefData::default();
    let bridge_addr = "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string();
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res, None);
    let mut transaction_message = TransactionMessage::default();
    transaction_message.info.msg_type = MessageType::ExternalIn as u8;
    maybe_ref.data = Some(transaction_message.clone());
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res, None);
    transaction_message.info.msg_type = MessageType::ExternalOut as u8;
    maybe_ref.data = Some(transaction_message.clone());
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res, None);
    transaction_message.info.src = TonAddress::from_str(&bridge_addr.clone()).unwrap();
    maybe_ref.data = Some(transaction_message.clone());
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res, None);

    transaction_message.body.cell_ref = Some((None, None));
    maybe_ref.data = Some(transaction_message.clone());
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res, None);

    let any_cell = AnyCell::default();
    transaction_message.body.cell_ref = Some((Some(any_cell.clone()), None));
    maybe_ref.data = Some(transaction_message.clone());
    let res = Bridge::validate_transaction_out_msg(maybe_ref.clone(), bridge_addr.clone());
    assert_eq!(res.unwrap(), any_cell.cell);
}

#[test]
fn test_handle_packet_receive() {
    let mut deps = mock_dependencies();
    let deps_mut = deps.as_mut();
    let storage = deps_mut.storage;
    let api = deps_mut.api;
    let querier = deps_mut.querier;
    let env = mock_env();
    let current_timestamp = env.block.time.seconds() + DEFAULT_TIMEOUT;
    let mut bridge_packet_data = BridgePacketData::default();
    bridge_packet_data.amount = Uint128::from(1000000000u128);
    bridge_packet_data.src_denom = "orai".to_string();
    bridge_packet_data.dest_denom = "orai".to_string();
    bridge_packet_data.orai_address = "orai_address".to_string();
    bridge_packet_data.src_channel = "channel-0".to_string();
    let mapping = MappingMetadata {
        asset_info: AssetInfo::NativeToken {
            denom: "orai".to_string(),
        },
        remote_decimals: 6,
        asset_info_decimals: 6,
        opcode: OPCODE_2,
        crc_src: 3724195509,
    };
    CONFIG
        .save(
            storage,
            &Config {
                validator_contract_addr: Addr::unchecked("validator"),
                bridge_adapter: "bridge_adapter".to_string(),
                relayer_fee_token: AssetInfo::NativeToken {
                    denom: "orai".to_string(),
                },
                relayer_fee: Uint128::from(100000u128),
                token_fee_receiver: Addr::unchecked("token_fee_receiver"),
                relayer_fee_receiver: Addr::unchecked("relayer_fee_receiver"),
                swap_router_contract: RouterController("router".to_string()),
            },
        )
        .unwrap();
    TOKEN_FEE
        .save(
            storage,
            "orai",
            &Ratio {
                nominator: 1,
                denominator: 1000,
            },
        )
        .unwrap();

    // case 1: timeout
    let res = Bridge::handle_packet_receive(
        storage,
        api,
        &querier,
        current_timestamp,
        bridge_packet_data.clone(),
        mapping.clone(),
    )
    .unwrap();

    assert_eq!(res.0.len(), 0);
    assert_eq!(res.1[0].value, "timeout".to_string());

    // case 2: happy case
    bridge_packet_data.timeout_timestamp = current_timestamp;
    Bridge::handle_packet_receive(
        storage,
        api,
        &querier,
        current_timestamp,
        bridge_packet_data.clone(),
        mapping,
    )
    .unwrap();

    let key = build_commitment_key(&bridge_packet_data.src_channel, bridge_packet_data.seq);
    let commitment = ACK_COMMITMENT.load(deps.as_ref().storage, &key).unwrap();
    assert_eq!(commitment, build_ack_commitment(0).unwrap().as_slice());
}

#[test]
fn test_read_transaction() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        cw20_addr,
        validator_addr,
        ..
    } = new_mock_app();

    // update bridge adapter contract
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: None,
                bridge_adapter: Some(
                    "EQBy38YFj_k18VCeFYElCppp_lzS8fc26qZ_XvEwKUBQbe17".to_string(),
                ),
                relayer_fee_token: None,
                token_fee_receiver: None,
                relayer_fee_receiver: None,
                relayer_fee: None,
                swap_router_contract: None,
                token_fee: None,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    let tx_boc = HexBinary::from_hex("b5ee9c720102140100036c0003b5772dfc6058ff935f1509e1581250a9a69fe5cd2f1f736eaa67f5ef1302940506d00002b38f30edb0110b3ab4393cbe2fb1708b43f55c6d24e909325544c94bb7de64cfd0fa2bdb7a900002b38f2a40b4366866a4a0005469dc4a680102030201e004050082729cc85b33466874bc28b8678bb2f9769358986535f948d63306bb4297e61ba1ecb785117fa81768757a416242202a4f2d412533ae25f9c4be7ef416ecfa1c152e02170444090e08871c186794d211121301b1680026199d4cf9ecc6786607ea6ab5d07ebb2b7300531ce1d62713126b93e9b547fb001cb7f18163fe4d7c542785604942a69a7f9734bc7dcdbaa99fd7bc4c0a50141b50e08871c0061739e200005671e5a3a404cd0cd47ec0060201dd090a0118af35dc85000000000000000007025dffff800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01be6030d4000000000cd0cefb10e0800438002dca7653b4c646d7d66400ffc787b1f6d70e8a404e3438ee55e6376927dfb19d00101200b0101200c00c94800e5bf8c0b1ff26be2a13c2b024a1534d3fcb9a5e3ee6dd54cfebde2605280a0db0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63390df7d6d800608235a00005671e61db604cd0cd4946a993b6d800000000000000040019fe00396fe302c7fc9af8a84f0ac092854d34ff2e6978fb9b75533faf789814a02836b009280cf31dd9d4f328084b3b6dc433d204ee97852960f7c44ce2c4170ce15a07c00002b38f30edb0366866a4a600d01b9a64c12a3000000000000000100000000668677d8800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01bf0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63380000c061a8200e0400100f101100126368616e6e656c2d30000000566f72616931717478346d6b77356b363635736e74376a6a397567356439303233686b7a6175656873303477009e44da2c3d09000000000000000000c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b26b04c48eecc000000000004000000000004db981dbe2b040c835c86fb376b39824f59ff18cc098a56d73637003e7730a2f041d050ec").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c72010218010003b800094603cabd47e29905535c1cb6bd1d13e65d5964f1fcc0553832fab37fd4a949eb8cbd002f01241011ef55aaffffff110203040502a09bc7a98700000000800102a514ee000000010200000000400000000000000066866a4a00002b38f30edb0000002b38f30edb25f462d25d0008e68d024fdd80024fd70fc400000007000000000000002e060728480101873b5b9dffd07b384b284ea21ac3530f658967fdb53d3f4a40c99e9d8ccb480d000228480101de3a40b5e184642ac1b5f24b045f57fdc84f73b4c67cbe7710e0ee44341995a9002e23894a33f6fd9c4126d2341735c35f5ef16400f2f0adc48df7648e72f040ca029a8d540dfb44af2543ace73486fe3afffbacaff2d4ec8b98f912a2b6d9cc59048ec39b1c6aae4008090a009800002b38f2ff98c4024fdd80aaa7fd3361c83dbec98a0e98b844e27b93510b80ad3d8ca9aafcd0269b598f7e24fbea4956ef8dea29c2afcdf5ea1f5d6e844d989c1d21db0c0403465c082928009800002b38f2f0569902a514ed9a25eed69ca32d5aec01a95c9a6c799e355507c398f2e634278eb6c027ce839446447fe0d3ec7ede900194c06888c58eeb2f92c8bc9332d9e380c2f6c6dc765e2848010162c3b2719195ebb25685ee79db143fda458d0052ef9f3349557f733930fcea580018284801019e17dce0fd8719de44c5aae6bfc4b4f3f52c0c58fc97b7b4fb8ad449aa30fac300192109a07811ccba0b220b6503c08e65d00c0d28480101b7a846a9b6ac493a45f93160e1de82409440c53d50670ab1048b0c28d17abff30016220910293a66e10e0f284801014cb3243d59f374affe4798537d20ed5eccf4105b2ba3bb8eebb5fdf57681c025001022091021739b1110112209101dcfb6c9121328480101b3eaa736f94756f6c24033e5a4fcd78fdee666c337663322ead4f7e581d85a74000722070e91e1311415284801010db5084e0a924af092597a7c905e07e13bfdd6bf59f5c91218df1644af8aa0c90015284801014e9da749c8d262966f54a86a77e1865d1f0e519b6318ddf5cde9470d4b2ecc03000722a3be5bf8c0b1ff26be2a13c2b024a1534d3fcb9a5e3ee6dd54cfebde2605280a0da69dc4a6572dfc6058ff935f1509e1581250a9a69fe5cd2f1f736eaa67f5ef1302940506da00000159c79876d809a77129a0161728480101cb2b34c6d56d41fc747b81e3b87c5bb95fc4ed7412eda2f0349a777d607b0e3f00070082729cc85b33466874bc28b8678bb2f9769358986535f948d63306bb4297e61ba1ecb785117fa81768757a416242202a4f2d412533ae25f9c4be7ef416ecfa1c152e").unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let token_denom = "EQB-MPwrd1G6WKNkLz_VnV6WqBDd142KMQv-g1O-8QUA3728";
    let packet_timeout_timestamp = 1720088536u64;

    let mut block_info = app.block_info();
    block_info.time = Timestamp::from_seconds(packet_timeout_timestamp - 10);
    app.set_block(block_info);

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                UpdatePairMsg {
                    local_channel_id: "channel-0".to_string(),
                    denom: token_denom.to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode,
                    crc_src: 3724195509,
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // case 1: read tx failed, block not verify,

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
                tx_proof: tx_proof.clone(),
                tx_boc: tx_boc.clone(),
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap_err();

    // shard block with block hash
    let block_hash =
        HexBinary::from_hex("cabd47e29905535c1cb6bd1d13e65d5964f1fcc0553832fab37fd4a949eb8cbd")
            .unwrap();

    // set verified for simplicity
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: validator_addr.to_string(),
            msg: to_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
                root_hash: block_hash,
                seq_no: 1,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
                tx_proof,
                tx_boc,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // query channel state
    let res: ChannelResponse = app
        .wrap()
        .query_wasm_smart(
            bridge_addr.clone(),
            &BridgeQueryMsg::ChannelStateData {
                channel_id: "channel-0".to_string(),
            },
        )
        .unwrap();

    assert_eq!(
        res,
        ChannelResponse {
            balances: vec![Amount::Native(coin(100000, token_denom))],
            total_sent: vec![Amount::Native(coin(100000, token_denom))],
        }
    );
}

#[test]
fn test_bridge_native_to_ton() {
    let mut deps = mock_dependencies();
    let denom = "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB";
    instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        InstantiateMsg {
            validator_contract_addr: Addr::unchecked("validator_contract_addr"),
            bridge_adapter: "bridge_adapter".to_string(),
            relayer_fee_token: AssetInfo::NativeToken {
                denom: "orai".to_string(),
            },
            token_fee_receiver: Addr::unchecked("token_fee_receiver"),
            relayer_fee_receiver: Addr::unchecked("relayer_fee_receiver"),
            relayer_fee: None,
            swap_router_contract: "swap_router_contract".to_string(),
        },
    )
    .unwrap();

    // case 1: failed, no funds
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
            local_channel_id: "channel-0".to_string(),
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "No funds sent");

    // case 2: failed, not mapping pair
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "orai")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
            local_channel_id: "channel-0".to_string(),
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap_err();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        ExecuteMsg::UpdateMappingPair(UpdatePairMsg {
            local_channel_id: "channel-0".to_string(),
            denom: denom.to_string(),
            local_asset_info: AssetInfo::NativeToken {
                denom: "orai".to_string(),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            crc_src: 3724195509,
        }),
    )
    .unwrap();

    // case 4: maping pair is invalid
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "atom")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
            local_channel_id: "channel-0".to_string(),
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), ContractError::InvalidFund {}.to_string());

    // case 5: failed, channel don't exist
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "orai")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
            local_channel_id: "channel-0".to_string(),
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Generic error: Channel does not exist");

    // case 6: success
    increase_channel_balance(
        deps.as_mut().storage,
        "channel-0",
        denom,
        Uint128::from(1000000000u128),
    )
    .unwrap();
    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "orai")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
            local_channel_id: "channel-0".to_string(),
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap();
    assert_eq!(res.messages, vec![]);
    assert_eq!(
        res.attributes,
        vec![
            ("action", "bridge_to_ton"),
            ("local_sender", "sender"),
            (
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            ("dest_denom", denom),
            ("local_amount", "10000"),
            ("crc_src", &3724195509u32.to_string()),
            ("relayer_fee", "0"),
            ("token_fee", "0"),
            (
                "timeout",
                &mock_env()
                    .block
                    .time
                    .plus_seconds(3600)
                    .seconds()
                    .to_string()
            ),
            ("remote_amount", "10000"),
            ("seq", "1"),
        ]
    );
}

#[test]
fn test_bridge_cw20_to_ton() {
    let mut deps = mock_dependencies();
    instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        InstantiateMsg {
            validator_contract_addr: Addr::unchecked("validator_contract_addr"),
            bridge_adapter: "bridge_adapter".to_string(),
            relayer_fee_token: AssetInfo::NativeToken {
                denom: "orai".to_string(),
            },
            token_fee_receiver: Addr::unchecked("token_fee_receiver"),
            relayer_fee_receiver: Addr::unchecked("relayer_fee_receiver"),
            relayer_fee: None,
            swap_router_contract: "swap_router_contract".to_string(),
        },
    )
    .unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        ExecuteMsg::UpdateMappingPair(UpdatePairMsg {
            local_channel_id: "channel-0".to_string(),
            denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
            local_asset_info: AssetInfo::Token {
                contract_addr: Addr::unchecked("usdt"),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            crc_src: 3724195509,
        }),
    )
    .unwrap();

    increase_channel_balance(
        deps.as_mut().storage,
        "channel-0",
        "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB",
        Uint128::from(1000000000u128),
    )
    .unwrap();

    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("usdt", &vec![]),
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: "sender".to_string(),
            amount: Uint128::from(10000u128),
            msg: to_binary(&BridgeToTonMsg {
                local_channel_id: "channel-0".to_string(),
                to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                timeout: None,
            })
            .unwrap(),
        }),
    )
    .unwrap();
    assert_eq!(res.messages, vec![]);
    assert_eq!(
        res.attributes,
        vec![
            attr("action", "bridge_to_ton"),
            attr("local_sender", "sender"),
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "10000"),
            attr("crc_src", &3724195509u32.to_string()),
            attr("relayer_fee", "0"),
            attr("token_fee", "0"),
            attr(
                "timeout",
                &mock_env()
                    .block
                    .time
                    .plus_seconds(3600)
                    .seconds()
                    .to_string()
            ),
            attr("remote_amount", "10000"),
            attr("seq", "1"),
        ]
    );
}

#[test]
fn test_bridge_to_ton_with_fee() {
    let mut deps = mock_dependencies();
    instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        InstantiateMsg {
            validator_contract_addr: Addr::unchecked("validator_contract_addr"),
            bridge_adapter: "bridge_adapter".to_string(),
            relayer_fee_token: AssetInfo::Token {
                contract_addr: Addr::unchecked("orai"),
            },
            token_fee_receiver: Addr::unchecked("token_fee_receiver"),
            relayer_fee_receiver: Addr::unchecked("relayer_fee_receiver"),
            relayer_fee: Some(Uint128::from(1000u128)),
            swap_router_contract: "swap_router_contract".to_string(),
        },
    )
    .unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        ExecuteMsg::UpdateMappingPair(UpdatePairMsg {
            local_channel_id: "channel-0".to_string(),
            denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
            local_asset_info: AssetInfo::Token {
                contract_addr: Addr::unchecked("orai"),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            crc_src: 3724195509,
        }),
    )
    .unwrap();

    // add token fee
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        ExecuteMsg::UpdateConfig {
            validator_contract_addr: None,
            bridge_adapter: None,
            relayer_fee_token: None,
            token_fee_receiver: None,
            relayer_fee_receiver: None,
            relayer_fee: None,
            swap_router_contract: None,
            token_fee: Some(vec![TokenFee {
                token_denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                ratio: Ratio {
                    nominator: 1,
                    denominator: 1000,
                },
            }]),
        },
    )
    .unwrap();

    increase_channel_balance(
        deps.as_mut().storage,
        "channel-0",
        "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB",
        Uint128::from(1000000000u128),
    )
    .unwrap();

    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("orai", &vec![]),
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: "sender".to_string(),
            amount: Uint128::from(10000u128),
            msg: to_binary(&BridgeToTonMsg {
                local_channel_id: "channel-0".to_string(),
                to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                timeout: None,
            })
            .unwrap(),
        }),
    )
    .unwrap();
    assert_eq!(
        res.messages,
        vec![
            SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: "orai".to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: "token_fee_receiver".to_string(),
                    amount: Uint128::from(10u128)
                })
                .unwrap(),
                funds: vec![],
            })),
            SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: "orai".to_string(),
                msg: to_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: "relayer_fee_receiver".to_string(),
                    amount: Uint128::from(1000u128)
                })
                .unwrap(),
                funds: vec![],
            }))
        ]
    );
    assert_eq!(
        res.attributes,
        vec![
            attr("action", "bridge_to_ton"),
            attr("local_sender", "sender"),
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "8990"),
            attr("crc_src", &3724195509u32.to_string()),
            attr("relayer_fee", "1000"),
            attr("token_fee", "10"),
            attr(
                "timeout",
                &mock_env()
                    .block
                    .time
                    .plus_seconds(3600)
                    .seconds()
                    .to_string()
            ),
            attr("remote_amount", "8990"),
            attr("seq", "1"),
        ]
    );

    // try change to other relayer fee and we cannot simualate swap, so relayer fee = 0

    // add token fee
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info("owner", &vec![]),
        ExecuteMsg::UpdateConfig {
            validator_contract_addr: None,
            bridge_adapter: None,
            relayer_fee_token: Some(AssetInfo::Token {
                contract_addr: Addr::unchecked("usdc"),
            }),
            token_fee_receiver: None,
            relayer_fee_receiver: None,
            relayer_fee: None,
            swap_router_contract: None,
            token_fee: None,
        },
    )
    .unwrap();
    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("orai", &vec![]),
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: "sender".to_string(),
            amount: Uint128::from(10000u128),
            msg: to_binary(&BridgeToTonMsg {
                local_channel_id: "channel-0".to_string(),
                to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                timeout: None,
            })
            .unwrap(),
        }),
    )
    .unwrap();
    assert_eq!(
        res.messages,
        vec![SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: "orai".to_string(),
            msg: to_binary(&Cw20ExecuteMsg::Transfer {
                recipient: "token_fee_receiver".to_string(),
                amount: Uint128::from(10u128)
            })
            .unwrap(),
            funds: vec![],
        })),]
    );
    assert_eq!(
        res.attributes,
        vec![
            attr("action", "bridge_to_ton"),
            attr("local_sender", "sender"),
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "9990"),
            attr("crc_src", &3724195509u32.to_string()),
            attr("relayer_fee", "0"),
            attr("token_fee", "10"),
            attr(
                "timeout",
                &mock_env()
                    .block
                    .time
                    .plus_seconds(3600)
                    .seconds()
                    .to_string()
            ),
            attr("remote_amount", "9990"),
            attr("seq", "2"),
        ]
    );
}

#[test]
fn test_bridge_ton_to_orai_with_fee() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        cw20_addr,
        validator_addr,
        ..
    } = new_mock_app();
    // update bridge adapter contract
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: None,
                bridge_adapter: Some(
                    "EQBy38YFj_k18VCeFYElCppp_lzS8fc26qZ_XvEwKUBQbe17".to_string(),
                ),
                relayer_fee_token: None,
                token_fee_receiver: None,
                relayer_fee_receiver: None,
                relayer_fee: None,
                swap_router_contract: None,
                token_fee: None,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    let tx_boc = HexBinary::from_hex("b5ee9c720102140100036c0003b5772dfc6058ff935f1509e1581250a9a69fe5cd2f1f736eaa67f5ef1302940506d00002b38f30edb0110b3ab4393cbe2fb1708b43f55c6d24e909325544c94bb7de64cfd0fa2bdb7a900002b38f2a40b4366866a4a0005469dc4a680102030201e004050082729cc85b33466874bc28b8678bb2f9769358986535f948d63306bb4297e61ba1ecb785117fa81768757a416242202a4f2d412533ae25f9c4be7ef416ecfa1c152e02170444090e08871c186794d211121301b1680026199d4cf9ecc6786607ea6ab5d07ebb2b7300531ce1d62713126b93e9b547fb001cb7f18163fe4d7c542785604942a69a7f9734bc7dcdbaa99fd7bc4c0a50141b50e08871c0061739e200005671e5a3a404cd0cd47ec0060201dd090a0118af35dc85000000000000000007025dffff800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01be6030d4000000000cd0cefb10e0800438002dca7653b4c646d7d66400ffc787b1f6d70e8a404e3438ee55e6376927dfb19d00101200b0101200c00c94800e5bf8c0b1ff26be2a13c2b024a1534d3fcb9a5e3ee6dd54cfebde2605280a0db0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63390df7d6d800608235a00005671e61db604cd0cd4946a993b6d800000000000000040019fe00396fe302c7fc9af8a84f0ac092854d34ff2e6978fb9b75533faf789814a02836b009280cf31dd9d4f328084b3b6dc433d204ee97852960f7c44ce2c4170ce15a07c00002b38f30edb0366866a4a600d01b9a64c12a3000000000000000100000000668677d8800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01bf0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63380000c061a8200e0400100f101100126368616e6e656c2d30000000566f72616931717478346d6b77356b363635736e74376a6a397567356439303233686b7a6175656873303477009e44da2c3d09000000000000000000c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b26b04c48eecc000000000004000000000004db981dbe2b040c835c86fb376b39824f59ff18cc098a56d73637003e7730a2f041d050ec").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c72010218010003b800094603cabd47e29905535c1cb6bd1d13e65d5964f1fcc0553832fab37fd4a949eb8cbd002f01241011ef55aaffffff110203040502a09bc7a98700000000800102a514ee000000010200000000400000000000000066866a4a00002b38f30edb0000002b38f30edb25f462d25d0008e68d024fdd80024fd70fc400000007000000000000002e060728480101873b5b9dffd07b384b284ea21ac3530f658967fdb53d3f4a40c99e9d8ccb480d000228480101de3a40b5e184642ac1b5f24b045f57fdc84f73b4c67cbe7710e0ee44341995a9002e23894a33f6fd9c4126d2341735c35f5ef16400f2f0adc48df7648e72f040ca029a8d540dfb44af2543ace73486fe3afffbacaff2d4ec8b98f912a2b6d9cc59048ec39b1c6aae4008090a009800002b38f2ff98c4024fdd80aaa7fd3361c83dbec98a0e98b844e27b93510b80ad3d8ca9aafcd0269b598f7e24fbea4956ef8dea29c2afcdf5ea1f5d6e844d989c1d21db0c0403465c082928009800002b38f2f0569902a514ed9a25eed69ca32d5aec01a95c9a6c799e355507c398f2e634278eb6c027ce839446447fe0d3ec7ede900194c06888c58eeb2f92c8bc9332d9e380c2f6c6dc765e2848010162c3b2719195ebb25685ee79db143fda458d0052ef9f3349557f733930fcea580018284801019e17dce0fd8719de44c5aae6bfc4b4f3f52c0c58fc97b7b4fb8ad449aa30fac300192109a07811ccba0b220b6503c08e65d00c0d28480101b7a846a9b6ac493a45f93160e1de82409440c53d50670ab1048b0c28d17abff30016220910293a66e10e0f284801014cb3243d59f374affe4798537d20ed5eccf4105b2ba3bb8eebb5fdf57681c025001022091021739b1110112209101dcfb6c9121328480101b3eaa736f94756f6c24033e5a4fcd78fdee666c337663322ead4f7e581d85a74000722070e91e1311415284801010db5084e0a924af092597a7c905e07e13bfdd6bf59f5c91218df1644af8aa0c90015284801014e9da749c8d262966f54a86a77e1865d1f0e519b6318ddf5cde9470d4b2ecc03000722a3be5bf8c0b1ff26be2a13c2b024a1534d3fcb9a5e3ee6dd54cfebde2605280a0da69dc4a6572dfc6058ff935f1509e1581250a9a69fe5cd2f1f736eaa67f5ef1302940506da00000159c79876d809a77129a0161728480101cb2b34c6d56d41fc747b81e3b87c5bb95fc4ed7412eda2f0349a777d607b0e3f00070082729cc85b33466874bc28b8678bb2f9769358986535f948d63306bb4297e61ba1ecb785117fa81768757a416242202a4f2d412533ae25f9c4be7ef416ecfa1c152e").unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let token_denom = "EQB-MPwrd1G6WKNkLz_VnV6WqBDd142KMQv-g1O-8QUA3728";
    let packet_timeout_timestamp = 1720088536u64;

    let mut block_info = app.block_info();
    block_info.time = Timestamp::from_seconds(packet_timeout_timestamp - 10);
    app.set_block(block_info);
    // update fee
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: None,
                bridge_adapter: None,
                relayer_fee_token: Some(AssetInfo::Token {
                    contract_addr: cw20_addr.clone(),
                }),
                token_fee_receiver: None,
                relayer_fee_receiver: None,
                relayer_fee: Some(Uint128::from(1000u128)),
                swap_router_contract: None,
                token_fee: Some(vec![TokenFee {
                    token_denom: token_denom.to_string(),
                    ratio: Ratio {
                        nominator: 1,
                        denominator: 1000,
                    },
                }]),
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                UpdatePairMsg {
                    local_channel_id: "channel-0".to_string(),
                    denom: token_denom.to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode,
                    crc_src: 3724195509,
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // shard block with block hash
    let block_hash =
        HexBinary::from_hex("cabd47e29905535c1cb6bd1d13e65d5964f1fcc0553832fab37fd4a949eb8cbd")
            .unwrap();

    // set verified for simplicity
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: validator_addr.to_string(),
            msg: to_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
                root_hash: block_hash,
                seq_no: 1,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
                tx_proof,
                tx_boc,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // try query fee balance
    let relayer_balance: BalanceResponse = app
        .wrap()
        .query_wasm_smart(
            cw20_addr.clone(),
            &cw20_base::msg::QueryMsg::Balance {
                address: "relayer_fee".to_string(),
            },
        )
        .unwrap();
    assert_eq!(relayer_balance.balance, Uint128::from(1000u128));
    let token_fee_balance: BalanceResponse = app
        .wrap()
        .query_wasm_smart(
            cw20_addr.clone(),
            &cw20_base::msg::QueryMsg::Balance {
                address: "token_fee".to_string(),
            },
        )
        .unwrap();
    assert_eq!(token_fee_balance.balance, Uint128::from(100u128));
}
