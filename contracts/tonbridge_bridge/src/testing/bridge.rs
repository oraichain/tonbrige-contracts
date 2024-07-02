use cosmwasm_schema::serde::de;
use cosmwasm_std::{
    attr, coin,
    testing::{mock_dependencies, mock_env, mock_info},
    to_binary, Addr, CosmosMsg, HexBinary, SubMsg, Uint128, WasmMsg,
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
    state::{Config, MappingMetadata, Ratio, TokenFee},
};
use tonbridge_parser::{types::BridgePacketData, OPCODE_2};
use tonlib::{
    address::TonAddress,
    responses::{AnyCell, MaybeRefData, MessageType, TransactionMessage},
};

use crate::{
    bridge::{Bridge, DEFAULT_TIMEOUT, SEND_TO_TON_MAGIC_NUMBER},
    channel::increase_channel_balance,
    contract::{execute, instantiate},
    error::ContractError,
    state::{CONFIG, TOKEN_FEE},
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
    transaction_message.info.src = TonAddress::from_base64_url(&bridge_addr.clone()).unwrap();
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
    let mapping = MappingMetadata {
        asset_info: AssetInfo::NativeToken {
            denom: "orai".to_string(),
        },
        remote_decimals: 6,
        asset_info_decimals: 6,
        opcode: OPCODE_2,
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
    let res = Bridge::handle_packet_receive(
        storage,
        api,
        &querier,
        current_timestamp,
        bridge_packet_data.clone(),
        mapping,
    )
    .unwrap();
    println!("res: {:?}", res);
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
                    "EQDZfQX89gMo3HAiW1tSK9visb2gouUvDCt6PODo3qkXKeox".to_string(),
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

    let tx_boc = HexBinary::from_hex("b5ee9c720102140100036f0003b57d97d05fcf60328dc70225b5b522bdbe2b1bda0a2e52f0c2b7a3ce0e8dea9172900001513ba0d5d85fc0a773e4754705ea84026db44fbeaaca1e2baf0dd5dedfe39db629d4958734300001513ba0d5d8166828e58000546a6690680102030201e00405008272dcb41d4bf971f06092f6eecdbf898756d673d77735a4e84ae7d12925d9b7c0baf82aaff12d7b49ab7b07f3867ae213de3521afd2baa482b651cc317c41c049b2021504091cee16fc18681bfa11121301b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700365f417f3d80ca371c0896d6d48af6f8ac6f6828b94bc30ade8f383a37aa45ca51cee16fc006175b3800002a27741abb08cd051cb0c0060201dd090a0118af35dc850000000000000000070261ffff800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034abd1a94a20002fbc2afd93dc58010e080043800536affe20d6af471ee32332b9ebfa93e271bd0d924f1e3bc5f0dce4860a07c5100101200b0101200c00c94801b2fa0bf9ec0651b8e044b6b6a457b7c5637b4145ca5e1856f479c1d1bd522e53000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a11cdc586800608235a00002a27741abb0ccd051cb06a993b6d800000000000000040019fe006cbe82fe7b01946e38112dada915edf158ded05172978615bd1e70746f548b94b003cb93f68a17ddadc9e1033a70011995f47a9ca4b7f154529567ed2a85365ea3600001513ba0d5d8766828e58600d01bd4b9c032d000000000000000017de157ec9ee2c00800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034b000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a000017a35294400200e0400100f101100126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e4530ac3d09000000000000000000c200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b33304c4952cc000000000004000000000004d7b30c9a07a17122303e6553a62e1d950e281e9004aa667753aa60229513e7b041d0516c").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c720102120100032c00094603a3cb391146df5705d742be39ac98c524e855432deb2ee6b1f82fe6f799fcef2d002001241011ef55aafffffffd0203040502a09bc7a9870000000084010151a1d4000000000200000000c00000000000000066828e5800001513ba0d5d8000001513ba0d5d88837ff5db0004556a013aba55013ab763c40000000800000000000001ee060728480101f3dc120bc609815b58aef43dbe778b2f3093f4b0dad0696d679493c152257f370001284801014dae1684965192171ff59dac6926af8723434cb423fe202778ac41f464950d3d001f23894a33f6fd5480343a842774e357cd56897609f3c5c8588c8b3c283f5b18285bb8807be560d6d6de6dc2167c056be8dbe0b6730d78710e2f5a23925744e5d42bb06f83f2d94008090a009800001513b9eed904013aba55b50e708866382195a989f99d8da25bc54877f2aec6daaaf75f7cf3e9972a145ae5440af7377ce89a83f2d8358dbed3178fcb2a0ade86abcb6bcbf90182b59535009800001513b9fe1b410151a1d3212289c6d0fb1539609cdd394bc23531bcba82f753e5a9dbd9a6cee888c4030d886e635a5ed24d2f249a2d9d0b6dda7ebf13d4d3fa6793d8d8fd99d79506b47a284801015b7e35806d90337174c4de9d01f675ea8383c808cb3d9c6a0e6fbba5085b7616001d28480101010eda12c8af2956eb710ab448f85c98be497f5fc519d2ad69e7601fb34566e4001c2109a00ba6e01a0b220b6d005d3700d00c0d23a3bf72fa0bf9ec0651b8e044b6b6a457b7c5637b4145ca5e1856f479c1d1bd522e5272b46f05d97d05fcf60328dc70225b5b522bdbe2b1bda0a2e52f0c2b7a3ce0e8dea917299e80000a89dd06aec0e568de100e0f10284801011d043a2d0fe2149600d727199be18bdaccd18347e5ed02fd482949d5c3f22432001b284801010f817018a69a0ce9a6de89a7faad4f9af47269dc9bad30be7d99560538bf20280008210964d4cd20d011008272ab568aad25dc4660ab5eb95d50378160501acbb2cbfa2ca5ff51e04f32008c8cf82aaff12d7b49ab7b07f3867ae213de3521afd2baa482b651cc317c41c049b228480101ab3fae260d0c12845931495c10fadc8b0335224544311638d48dd60d3d6eefa50007").unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();

    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                UpdatePairMsg {
                    local_channel_id: "channel-0".to_string(),
                    denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode,
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
        HexBinary::from_hex("a3cb391146df5705d742be39ac98c524e855432deb2ee6b1f82fe6f799fcef2d")
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
            balances: vec![Amount::Native(coin(
                1000000000000,
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ))],
            total_sent: vec![Amount::Native(coin(
                1000000000000,
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ))],
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
            crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            crc_src: SEND_TO_TON_MAGIC_NUMBER,
            timeout: None,
        }),
    )
    .unwrap();
    assert_eq!(res.messages, vec![]);
    assert_eq!(
        res.attributes,
        vec![
            ("action", "bridge_to_ton"),
            (
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            ("dest_denom", denom),
            ("local_amount", "10000"),
            ("crc_src", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
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
                crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "10000"),
            attr("crc_src", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
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
                crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "8990"),
            attr("crc_src", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
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
                crc_src: SEND_TO_TON_MAGIC_NUMBER,
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
            attr(
                "dest_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "dest_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "9990"),
            attr("crc_src", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
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
                    "EQDZfQX89gMo3HAiW1tSK9visb2gouUvDCt6PODo3qkXKeox".to_string(),
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

    let tx_boc = HexBinary::from_hex("b5ee9c720102140100036f0003b57d97d05fcf60328dc70225b5b522bdbe2b1bda0a2e52f0c2b7a3ce0e8dea9172900001513ba0d5d85fc0a773e4754705ea84026db44fbeaaca1e2baf0dd5dedfe39db629d4958734300001513ba0d5d8166828e58000546a6690680102030201e00405008272dcb41d4bf971f06092f6eecdbf898756d673d77735a4e84ae7d12925d9b7c0baf82aaff12d7b49ab7b07f3867ae213de3521afd2baa482b651cc317c41c049b2021504091cee16fc18681bfa11121301b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700365f417f3d80ca371c0896d6d48af6f8ac6f6828b94bc30ade8f383a37aa45ca51cee16fc006175b3800002a27741abb08cd051cb0c0060201dd090a0118af35dc850000000000000000070261ffff800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034abd1a94a20002fbc2afd93dc58010e080043800536affe20d6af471ee32332b9ebfa93e271bd0d924f1e3bc5f0dce4860a07c5100101200b0101200c00c94801b2fa0bf9ec0651b8e044b6b6a457b7c5637b4145ca5e1856f479c1d1bd522e53000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a11cdc586800608235a00002a27741abb0ccd051cb06a993b6d800000000000000040019fe006cbe82fe7b01946e38112dada915edf158ded05172978615bd1e70746f548b94b003cb93f68a17ddadc9e1033a70011995f47a9ca4b7f154529567ed2a85365ea3600001513ba0d5d8766828e58600d01bd4b9c032d000000000000000017de157ec9ee2c00800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034b000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a000017a35294400200e0400100f101100126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e4530ac3d09000000000000000000c200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b33304c4952cc000000000004000000000004d7b30c9a07a17122303e6553a62e1d950e281e9004aa667753aa60229513e7b041d0516c").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c720102120100032c00094603a3cb391146df5705d742be39ac98c524e855432deb2ee6b1f82fe6f799fcef2d002001241011ef55aafffffffd0203040502a09bc7a9870000000084010151a1d4000000000200000000c00000000000000066828e5800001513ba0d5d8000001513ba0d5d88837ff5db0004556a013aba55013ab763c40000000800000000000001ee060728480101f3dc120bc609815b58aef43dbe778b2f3093f4b0dad0696d679493c152257f370001284801014dae1684965192171ff59dac6926af8723434cb423fe202778ac41f464950d3d001f23894a33f6fd5480343a842774e357cd56897609f3c5c8588c8b3c283f5b18285bb8807be560d6d6de6dc2167c056be8dbe0b6730d78710e2f5a23925744e5d42bb06f83f2d94008090a009800001513b9eed904013aba55b50e708866382195a989f99d8da25bc54877f2aec6daaaf75f7cf3e9972a145ae5440af7377ce89a83f2d8358dbed3178fcb2a0ade86abcb6bcbf90182b59535009800001513b9fe1b410151a1d3212289c6d0fb1539609cdd394bc23531bcba82f753e5a9dbd9a6cee888c4030d886e635a5ed24d2f249a2d9d0b6dda7ebf13d4d3fa6793d8d8fd99d79506b47a284801015b7e35806d90337174c4de9d01f675ea8383c808cb3d9c6a0e6fbba5085b7616001d28480101010eda12c8af2956eb710ab448f85c98be497f5fc519d2ad69e7601fb34566e4001c2109a00ba6e01a0b220b6d005d3700d00c0d23a3bf72fa0bf9ec0651b8e044b6b6a457b7c5637b4145ca5e1856f479c1d1bd522e5272b46f05d97d05fcf60328dc70225b5b522bdbe2b1bda0a2e52f0c2b7a3ce0e8dea917299e80000a89dd06aec0e568de100e0f10284801011d043a2d0fe2149600d727199be18bdaccd18347e5ed02fd482949d5c3f22432001b284801010f817018a69a0ce9a6de89a7faad4f9af47269dc9bad30be7d99560538bf20280008210964d4cd20d011008272ab568aad25dc4660ab5eb95d50378160501acbb2cbfa2ca5ff51e04f32008c8cf82aaff12d7b49ab7b07f3867ae213de3521afd2baa482b651cc317c41c049b228480101ab3fae260d0c12845931495c10fadc8b0335224544311638d48dd60d3d6eefa50007").unwrap();

    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();

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
                    token_denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
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
                    denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode,
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // shard block with block hash
    let block_hash =
        HexBinary::from_hex("a3cb391146df5705d742be39ac98c524e855432deb2ee6b1f82fe6f799fcef2d")
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
    assert_eq!(token_fee_balance.balance, Uint128::from(1000000000u128));
}
