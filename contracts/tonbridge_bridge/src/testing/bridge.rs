use std::str::FromStr;

use cosmwasm_std::{
    attr, coin,
    testing::{mock_dependencies, mock_env, mock_info},
    to_binary, Addr, CosmosMsg, HexBinary, SubMsg, Uint128, WasmMsg,
};

use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20ReceiveMsg};
use cw20_ics20_msg::amount::Amount;
use cw_multi_test::Executor;
use cw_storage_plus::Endian;
use oraiswap::{asset::AssetInfo, router::RouterController};
use tonbridge_bridge::{
    msg::{
        BridgeToTonMsg, ChannelResponse, ExecuteMsg, InstantiateMsg, QueryMsg as BridgeQueryMsg,
        UpdatePairMsg,
    },
    state::{Config, MappingMetadata, Ratio, SendPacket, TokenFee},
};
use tonbridge_parser::{types::BridgePacketData, OPCODE_2};
use tonlib::{
    address::TonAddress,
    cell::{Cell, CellBuilder},
    responses::{AnyCell, MaybeRefData, MessageType, TransactionMessage},
};

use crate::{
    bridge::{Bridge, DEFAULT_TIMEOUT, SEND_TO_TON_MAGIC_NUMBER},
    channel::increase_channel_balance,
    contract::{execute, execute_submit_bridge_to_ton_info, instantiate},
    error::ContractError,
    state::{ics20_denoms, CONFIG, REMOTE_INITIATED_CHANNEL_STATE, SEND_PACKET, TOKEN_FEE},
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
    let mut mapping = MappingMetadata {
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

    let tx_boc = HexBinary::from_hex("b5ee9c72010210010002a00003b5704f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1000014c775004781596aa8bae813b9e6a71ade2ba8a393b7b1fff5c20db8414268e761e80f445466000014c774a4ba016675543a00034671e79e80102030201e00405008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d02170447c90ec90dd418656798110e0f01b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700013c6a766275015329cb0a4bff7c883117164beea1ad589953f1402dbbf7302850ec90dd400613faa00000298ee9a50184cceaa864c0060101df080118af35dc850000000000000000070155ffff801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d00010a019fe000278d4ecc4ea02a653961497fef910622e2c97dd435ab132a7e2805b77ee6050b006b6841e5c7db57b8d076dfa4368dea08e132f2917969b5920fbd8229dc6560d7000014c7750047826675543a60090153801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d0000100a04000c0b0c0d00126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e43758c3d090000000000000000008c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc986db784c36dbc000000000000200000000000390f7bed18b3fc226db7ad9ac1961b38a37b80e826f33ccabfa03d8405819e6ca41902b2c").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c7201020e010002cd00094603b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80001d01241011ef55aafffffffd0203040502a09bc7a987000000008401014ceab100000000020000000000000000000000006675543a000014c775004780000014c7750047831736f9b3000446e401361bf701361bd7c400000007000000000000002e06072848010169df3a129570f135f49a71d8b483fa4c1c482f3f66ed85120a88d1b12fa9d16500012848010140bc4dd799a511514e2389685f05400ff4552fd0742fa5bcffc54f5628ba2728001c23894a33f6fde40b062e4f9ca75cdd7575e0d2ad61010f65e76ead272c60375bbdf85721963d37da28343e390d3d0fcc100f52754cdd13a8e4b655b0b6d5953c09f2f928d8ce4008090a0098000014c774e1c30401361bf750761c553cb279919d5c01370e223caddc8aed39f253c97e2067fab0d970edb84dfe70fb36e9e9e40e03596ed1ede5e16b95c4ab61817ceac5e86ca43fd7b4480098000014c774f10543014ceab0eadce00e65f2d6771561346ad31884c67e036c6aa63d14ba694d6affdf684810f750e961923988298da0b1dbe93abce9756cc3ef6b72dfd97531c7ce6199cabb28480101a7f5bf430102522e84d0b8b108a45efc71925ce0c6c591ae5ac50e7ead9baa15000828480101db58517b1e79f67b35742f301a407f7edf1b95fae995d949f62cbeb17f10e0e60009210799c79e7a0b22a5a0009e353b313a80a994e58525ffbe44188b8b25f750d6ac4ca9f8a016ddfb98142671e79e504f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1a000000a63ba8023c099c79e7a00c0d28480101f12edcfd2cb61fdee42d31cd884d21f92891e1ef9072f3ba4dded90ea5a09f380006008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d").unwrap();

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
                    denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
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
        HexBinary::from_hex("b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80")
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
                1000000000000000,
                "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl"
            ))],
            total_sent: vec![Amount::Native(coin(
                1000000000000000,
                "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl"
            ))],
        }
    );
}

#[test]
fn test_bridge_native_to_ton() {
    let mut deps = mock_dependencies();
    let denom = "EQAcXN7ZRk927VwlwN66AHubcd-6X3VhiESEWsE2k63AICIN";
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
            denom: "EQAcXN7ZRk927VwlwN66AHubcd-6X3VhiESEWsE2k63AICIN".to_string(),
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
            denom: "orai_ton".to_string(),
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
            denom: "orai_ton".to_string(),
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
            denom: "orai_ton".to_string(),
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
        "orai_ton",
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
            denom: "orai_ton".to_string(),
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
            ("dest_denom", "orai_ton"),
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
            denom: "orai_ton".to_string(),
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
        "orai_ton",
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
                denom: "orai_ton".to_string(),
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
            attr("dest_denom", "orai_ton"),
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
fn test_submit_bridge_to_ton_info() {
    let mut deps = mock_dependencies();
    let env = mock_env();
    SEND_PACKET
        .save(
            deps.as_mut().storage,
            1,
            &SendPacket {
                sequence: 1,
                to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                denom: "EQAcXN7ZRk927VwlwN66AHubcd-6X3VhiESEWsE2k63AICIN".to_string(),
                amount: Uint128::from(10000000000u128),
                crc_src: SEND_TO_TON_MAGIC_NUMBER,
                timeout_timestamp: env.block.time.seconds() + DEFAULT_TIMEOUT,
            },
        )
        .unwrap();

    // seq = 2
    let data_err = "000000000000000280002255d73e3a5c1a9589f0aece31e97b54b261ac3d7d16d4f1068fdf9d4b4e18300071737b65193ddbb57097037ae801ee6dc77ee97dd5862112116b04da4eb70080000000000000000000000009502f9000139517d0000000019a07ba04";
    let res =
        execute_submit_bridge_to_ton_info(deps.as_mut(), HexBinary::from_hex(data_err).unwrap())
            .unwrap_err();
    assert!(res.to_string().contains("SendPacket not found"));

    // verify success
    let data = "000000000000000180002255d73e3a5c1a9589f0aece31e97b54b261ac3d7d16d4f1068fdf9d4b4e18300071737b65193ddbb57097037ae801ee6dc77ee97dd5862112116b04da4eb70080000000000000000000000009502f9000139517d00000000176bf1eec";
    let res = execute_submit_bridge_to_ton_info(deps.as_mut(), HexBinary::from_hex(data).unwrap())
        .unwrap();
    assert_eq!(
        res.attributes,
        vec![
            ("action", "submit_bridge_to_ton_info"),
            ("data", &data.to_lowercase())
        ]
    );

    // after submit, not found send_packet
    let packet = SEND_PACKET.may_load(deps.as_ref().storage, 1).unwrap();
    assert_eq!(packet, None);
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
            denom: "orai_ton".to_string(),
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
                token_denom: "orai_ton".to_string(),
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
        "orai_ton",
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
                denom: "orai_ton".to_string(),
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
            attr("dest_denom", "orai_ton"),
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
                denom: "orai_ton".to_string(),
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
            attr("dest_denom", "orai_ton"),
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

    let tx_boc = HexBinary::from_hex("b5ee9c72010210010002a00003b5704f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1000014c775004781596aa8bae813b9e6a71ade2ba8a393b7b1fff5c20db8414268e761e80f445466000014c774a4ba016675543a00034671e79e80102030201e00405008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d02170447c90ec90dd418656798110e0f01b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700013c6a766275015329cb0a4bff7c883117164beea1ad589953f1402dbbf7302850ec90dd400613faa00000298ee9a50184cceaa864c0060101df080118af35dc850000000000000000070155ffff801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d00010a019fe000278d4ecc4ea02a653961497fef910622e2c97dd435ab132a7e2805b77ee6050b006b6841e5c7db57b8d076dfa4368dea08e132f2917969b5920fbd8229dc6560d7000014c7750047826675543a60090153801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d0000100a04000c0b0c0d00126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e43758c3d090000000000000000008c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc986db784c36dbc000000000000200000000000390f7bed18b3fc226db7ad9ac1961b38a37b80e826f33ccabfa03d8405819e6ca41902b2c").unwrap();

    let tx_proof = HexBinary::from_hex("b5ee9c7201020e010002cd00094603b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80001d01241011ef55aafffffffd0203040502a09bc7a987000000008401014ceab100000000020000000000000000000000006675543a000014c775004780000014c7750047831736f9b3000446e401361bf701361bd7c400000007000000000000002e06072848010169df3a129570f135f49a71d8b483fa4c1c482f3f66ed85120a88d1b12fa9d16500012848010140bc4dd799a511514e2389685f05400ff4552fd0742fa5bcffc54f5628ba2728001c23894a33f6fde40b062e4f9ca75cdd7575e0d2ad61010f65e76ead272c60375bbdf85721963d37da28343e390d3d0fcc100f52754cdd13a8e4b655b0b6d5953c09f2f928d8ce4008090a0098000014c774e1c30401361bf750761c553cb279919d5c01370e223caddc8aed39f253c97e2067fab0d970edb84dfe70fb36e9e9e40e03596ed1ede5e16b95c4ab61817ceac5e86ca43fd7b4480098000014c774f10543014ceab0eadce00e65f2d6771561346ad31884c67e036c6aa63d14ba694d6affdf684810f750e961923988298da0b1dbe93abce9756cc3ef6b72dfd97531c7ce6199cabb28480101a7f5bf430102522e84d0b8b108a45efc71925ce0c6c591ae5ac50e7ead9baa15000828480101db58517b1e79f67b35742f301a407f7edf1b95fae995d949f62cbeb17f10e0e60009210799c79e7a0b22a5a0009e353b313a80a994e58525ffbe44188b8b25f750d6ac4ca9f8a016ddfb98142671e79e504f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1a000000a63ba8023c099c79e7a00c0d28480101f12edcfd2cb61fdee42d31cd884d21f92891e1ef9072f3ba4dded90ea5a09f380006008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d").unwrap();

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
                    token_denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
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
                    denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
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
        HexBinary::from_hex("b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80")
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
    assert_eq!(token_fee_balance.balance, Uint128::from(1000000000000u128));
}
