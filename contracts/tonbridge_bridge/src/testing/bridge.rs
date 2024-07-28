use std::str::FromStr;

use cosmwasm_std::{
    attr, coin,
    testing::{mock_dependencies, mock_env, mock_info},
    to_json_binary, Addr, Api, BlockInfo, CanonicalAddr, CosmosMsg, HexBinary, SubMsg, Timestamp,
    Uint128, WasmMsg,
};

use cosmwasm_testing_util::Executor;
use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20ReceiveMsg};

use oraiswap::{
    asset::{Asset, AssetInfo},
    router::RouterController,
};
use token_bindings::{
    DenomsByCreatorResponse, FullDenomResponse, Metadata, MetadataResponse, TokenFactoryMsg,
    TokenFactoryMsgOptions,
};
use tonbridge_bridge::{
    amount::Amount,
    msg::{
        BridgeToTonMsg, ChannelResponse, ExecuteMsg, InstantiateMsg, QueryMsg as BridgeQueryMsg,
        RegisterDenomMsg, UpdatePairMsg,
    },
    state::{Config, MappingMetadata, Ratio, TokenFee},
};
use tonbridge_parser::{
    transaction_parser::{RECEIVE_PACKET_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER},
    types::{BridgePacketData, Status, VdataHex},
    OPCODE_2,
};
use tonlib::{
    address::TonAddress,
    cell::CellBuilder,
    responses::{AnyCell, MaybeRefData, MessageType, TransactionMessage},
};

use crate::{
    adapter::{handle_packet_receive, DEFAULT_TIMEOUT},
    bridge::Bridge,
    channel::increase_channel_balance,
    contract::{execute, instantiate},
    error::ContractError,
    helper::{build_ack_commitment, build_burn_asset_msg, build_mint_asset_msg},
    state::{ACK_COMMITMENT, CONFIG, TOKEN_FEE},
    testing::mock::{new_mock_app, new_mock_app_with_boc, MockApp},
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

// FIXME: Wrong canonical address length
// #[test]
// fn test_handle_packet_receive() {
//     let mut deps = mock_dependencies();
//     let deps_mut = deps.as_mut();
//     let storage = deps_mut.storage;
//     let api = deps_mut.api;
//     let querier = deps_mut.querier;
//     let env = mock_env();
//     let current_timestamp = env.block.time.seconds() + DEFAULT_TIMEOUT;

//     let seq = 1;
//     let token_origin = 529034805;
//     let timeout_timestamp = env.block.time.seconds() - 100;
//     let src_sender = "EQCkkxPb0X4DAMBrOi8Tyf0wdqqVtTR9ekbDqB9ijP391nQh".to_string();
//     let src_denom = "EQCkkxPb0X4DAMBrOi8Tyf0wdqqVtTR9ekbDqB9ijP391nQh".to_string();
//     let amount = Uint128::from(1000000000u128);

//     let receiver_raw: Vec<u8> = vec![
//         23, 12, 3, 5, 13, 30, 10, 3, 20, 28, 27, 5, 31, 12, 11, 15, 3, 1, 22, 13, 21, 3, 30, 20,
//         12, 3, 16, 0, 11, 14, 26, 4,
//     ];
//     let receiver = CanonicalAddr::from(receiver_raw);

//     let mut bridge_packet_data = BridgePacketData {
//         seq,
//         token_origin,
//         timeout_timestamp,
//         src_sender: src_sender.clone(),
//         src_denom: src_denom.clone(),
//         amount,
//         receiver: receiver.clone(),
//         memo: None,
//     };

//     let mapping = MappingMetadata {
//         asset_info: AssetInfo::NativeToken {
//             denom: "orai".to_string(),
//         },
//         remote_decimals: 6,
//         asset_info_decimals: 6,
//         opcode: OPCODE_2,
//         token_origin: 529034805,
//     };
//     CONFIG
//         .save(
//             storage,
//             &Config {
//                 validator_contract_addr: Addr::unchecked("validator"),
//                 bridge_adapter: "bridge_adapter".to_string(),
//                 relayer_fee_token: AssetInfo::NativeToken {
//                     denom: "orai".to_string(),
//                 },
//                 relayer_fee: Uint128::from(100000u128),
//                 token_fee_receiver: Addr::unchecked("token_fee_receiver"),
//                 relayer_fee_receiver: Addr::unchecked("relayer_fee_receiver"),
//                 swap_router_contract: RouterController("router".to_string()),
//             },
//         )
//         .unwrap();
//     TOKEN_FEE
//         .save(
//             storage,
//             "orai",
//             &Ratio {
//                 nominator: 1,
//                 denominator: 1000,
//             },
//         )
//         .unwrap();

//     // case 1: timeout
//     let res = handle_packet_receive(
//         storage,
//         api,
//         &querier,
//         current_timestamp,
//         bridge_packet_data.clone(),
//         mapping.clone(),
//     )
//     .unwrap();

//     assert_eq!(res.0.len(), 0);
//     assert_eq!(res.1[0].value, "timeout".to_string());

//     // case 2: happy case
//     bridge_packet_data.timeout_timestamp = current_timestamp;
//     handle_packet_receive(
//         storage,
//         api,
//         &querier,
//         current_timestamp,
//         bridge_packet_data.clone(),
//         mapping,
//     )
//     .unwrap();

//     let commitment = ACK_COMMITMENT.load(deps.as_ref().storage, 1).unwrap();
//     assert_eq!(
//         commitment.to_be_bytes(),
//         build_ack_commitment(
//             seq,
//             token_origin,
//             amount,
//             timeout_timestamp,
//             receiver.as_slice(),
//             &src_denom,
//             &src_sender,
//             Status::Success
//         )
//         .unwrap()
//         .as_slice()
//     );
// }

// FIXME: Wrong canonical address length
// #[test]
// fn test_read_transaction() {
//     let MockApp {
//         mut app,
//         owner,
//         bridge_addr,
//         cw20_addr,
//         validator_addr,
//         ..
//     } = new_mock_app();

//     // update bridge adapter contract
//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: bridge_addr.to_string(),
//             msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
//                 validator_contract_addr: None,
//                 bridge_adapter: Some(
//                     "EQCWH9kCKpCTpswaygq-Ah7h-1vH3xZ3gJq7-SM6ZkYiOgHH".to_string(),
//                 ),
//                 relayer_fee_token: None,
//                 token_fee_receiver: None,
//                 relayer_fee_receiver: None,
//                 relayer_fee: None,
//                 swap_router_contract: None,
//                 token_fee: None,
//             })
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap();

//     let tx_boc = HexBinary::from_hex("b5ee9c72010211010003450003b57961fd9022a9093a6cc1aca0abe021ee1fb5bc7df1677809abbf9233a6646223a00002b5df4ae0c41591328d8b3673d4b795f57c789e145481d3b1d2413af77a28086813032f2cf0c00002b5df4527ec1668fba29000546e2689c80102030201e0040500827298457e3ebcfa880e4a67df0d88c69cca63a7ca8de9234ad23dbe051f586d8469b9aa5df59ef1ad564d84695fd6c9182ef92b205953a7da224579e187466403bb02170446c91cef574c186c1fe8110f1001b1680026199d4cf9ecc6786607ea6ab5d07ebb2b7300531ce1d62713126b93e9b547fb002587f6408aa424e9b306b282af8087b87ed6f1f7c59de026aefe48ce9991888e91cef574c00612b38a000056bbe9008b04cd1f743ac0060201dd08090118af35dc850000000000000000070285ffff800e538276dbe580f97e140d56c7a695e8a9e7a641d8379b1f6b8da49a100d42f8444e2000000000cd1f574c299beee0c4cf91a62d47583c7745120351acd2a5810e0d0101200a0101200b00c948012c3fb2045521274d983594157c043dc3f6b78fbe2cef013577f24674cc8c44750005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63391cd590dc00608235a000056bbe95c1884cd1f74526a993b6d800000000000000040019fe004b0fec81154849d3660d65055f010f70fdade3ef8b3bc04d5dfc919d3323111d30010926e9e39e0b6f991fe801420858017cc708d639ef898187dc61b9eac89901a00002b5df4ae0c43668fba29600c02bda64c12a300000000000000071f886e350000000000000000000000000000271000000000668faba614cdf7706267c8d316a3ac1e3ba28901a8d66952c0800e538276dbe580f97e140d56c7a695e8a9e7a641d8379b1f6b8da49a100d42f8500d0e00438002dca7653b4c646d7d66400ffc787b1f6d70e8a404e3438ee55e6376927dfb19d00000009e47c28c3d09000000000000000000f200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98a23504c40d3cc0000000000040000000000044acf306fc0346e061272572316da3988492c51b2df2a48f0fae17327c722d09c41504ccc").unwrap();

//     let tx_proof = HexBinary::from_hex("b5ee9c7201021a010003e800094603eb26d6f3d075f89f8ad8bb011a6814ec6a283c697cbcc0ca2450eaad97a06327002501241011ef55aaffffff110203040502a09bc7a98700000000800102a6fa0e0000000102000000008000000000000000668fba2900002b5df4ae0c4000002b5df4ae0c4d28b29c140008f0420252443f025228dbc400000007000000000000002e06072848010169134a3a596b68d647965f54a94d98fea6b8cdca27f61d5f8117859ae80f71460003284801017bdcfc2172b6c9e181490a9960cd7b90b44dd129ebc618a416f60c0144298d38002423894a33f6fde8a3fae01eb649213b6347684dcdd1bea74a224138fe572d3b2b41d156d02415ea2e404dd0ee02412f2a7791d30abd074ec16256fa83cd5376d4b0fbcfddf8df4008090a009800002b5df49eca040252443fadd1d2b79fce4fb274d594057b44704ff4a09d783433498401d7a3268998344d7d92a3baba00a520556b90da5731b089013a8491278cf99870417e8178cd5028009800002b5df49eca0a02a6fa0dad0968c77acc29e9847831a33ecf1005ea8b189a9fc33fc9a640718d23639083a9e2bf177215b1ed5d4f8737860e81c9f3ae9669024ecaedde03957abf34359a2848010126a390200ef92244737858b673f1eddffd1c0b96fc85d754efbdaab26a28ec2c001c284801019a90185f6324eab6c87c27f5a8ff53ea2a129b6b519e9d95f81c4dbb648b0cdf001c2109a0773e1bc20b220b6903b9f0de100c0d2209101d4c77b50e0f28480101d6b60f4f983236f3b9e6a5b198a318ecb28bb7b5b1df54711cdaf4142f300e85001928480101df692049ca7bbaa2a47bf4008e104f7f11838553b7883c8dc39d865f57145524001322091015c153d910112209100cb12509121328480101812da7fe1eab36c72bf9174ae0dfd6ed4477180a7090ed81503a3e27a3aa9fe9000d284801016a53739349b426fbaa9093865a46d4986f351f269f1a24e94596ab9afea86f05001322091008bed0f514152848010173151c552b62a83c7ff320b32184eb6219e12e8d6aaba1c40061cec12c5ca742000a22091004e5ff19161722a3be07f6408aa424e9b306b282af8087b87ed6f1f7c59de026aefe48ce9991888e8dc4d138b2c3fb2045521274d983594157c043dc3f6b78fbe2cef013577f24674cc8c44754000002b5df4ae0c41371344e40181928480101f8c0756de82229a358f03b021ba0c2cd31ddfcf3b220192248fd05b7ddfc425f001228480101f070dea8890cc35e161d5c3019d8e8b195dff34ffd2ef60b975727645296d338000600827298457e3ebcfa880e4a67df0d88c69cca63a7ca8de9234ad23dbe051f586d8469b9aa5df59ef1ad564d84695fd6c9182ef92b205953a7da224579e187466403bb").unwrap();

//     let opcode =
//         HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
//             .unwrap();
//     let token_denom = "EQBynBO23ywHy_CgarY9NK9FTz0yDsG82PtcbSTQgGoXwiuA";
//     let packet_timeout_timestamp = 1720691622u64;

//     let mut block_info = app.block_info();
//     block_info.time = Timestamp::from_seconds(packet_timeout_timestamp - 10);
//     app.set_block(block_info);

//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: bridge_addr.to_string(),
//             msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
//                 UpdatePairMsg {
//                     denom: token_denom.to_string(),
//                     local_asset_info: AssetInfo::Token {
//                         contract_addr: Addr::unchecked(cw20_addr.clone()),
//                     },
//                     remote_decimals: 6,
//                     local_asset_info_decimals: 6,
//                     opcode,
//                     token_origin: 529034805,
//                 },
//             ))
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap();

//     // case 1: read tx failed, block not verify,

//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: bridge_addr.to_string(),
//             msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
//                 tx_proof: tx_proof.clone(),
//                 tx_boc: tx_boc.clone(),
//             })
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap_err();

//     // shard block with block hash
//     let block_hash =
//         HexBinary::from_hex("eb26d6f3d075f89f8ad8bb011a6814ec6a283c697cbcc0ca2450eaad97a06327")
//             .unwrap();

//     // set verified for simplicity
//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: validator_addr.to_string(),
//             msg: to_json_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
//                 root_hash: block_hash,
//                 seq_no: 1,
//             })
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap();

//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: bridge_addr.to_string(),
//             msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
//                 tx_proof,
//                 tx_boc,
//             })
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap();

//     // query channel state
//     let res: ChannelResponse = app
//         .wrap()
//         .query_wasm_smart(bridge_addr.clone(), &BridgeQueryMsg::ChannelStateData {})
//         .unwrap();

//     assert_eq!(
//         res,
//         ChannelResponse {
//             balances: vec![Amount::Native(coin(100000, token_denom))],
//             total_sent: vec![Amount::Native(coin(100000, token_denom))],
//         }
//     );
// }

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
            token_factory_addr: None,
        },
    )
    .unwrap();

    // case 1: failed, no funds
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
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
            denom: denom.to_string(),
            local_asset_info: AssetInfo::NativeToken {
                denom: "orai".to_string(),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            token_origin: 529034805,
        }),
    )
    .unwrap();

    // case 4: maping pair is invalid
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "atom")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
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
            to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
            denom: denom.to_string(),
            timeout: None,
        }),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Generic error: Channel does not exist");

    // case 6: success
    increase_channel_balance(deps.as_mut().storage, denom, Uint128::from(1000000000u128)).unwrap();
    let res = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &vec![coin(10000, "orai")]),
        ExecuteMsg::BridgeToTon(BridgeToTonMsg {
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
            attr("action", "send_to_ton"),
            attr("opcode_packet", SEND_TO_TON_MAGIC_NUMBER.to_string()),
            attr("local_sender", "sender"),
            attr(
                "remote_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "remote_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "10000"),
            attr("token_origin", &529034805u32.to_string()),
            attr("relayer_fee", "0"),
            attr("token_fee", "0"),
            attr(
                "timeout_timestamp",
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
            token_factory_addr: None,
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
            denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
            local_asset_info: AssetInfo::Token {
                contract_addr: Addr::unchecked("usdt"),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            token_origin: 529034805,
        }),
    )
    .unwrap();

    increase_channel_balance(
        deps.as_mut().storage,
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
            msg: to_json_binary(&BridgeToTonMsg {
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
            attr("action", "send_to_ton"),
            attr("opcode_packet", SEND_TO_TON_MAGIC_NUMBER.to_string()),
            attr("local_sender", "sender"),
            attr(
                "remote_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "remote_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "10000"),
            attr("token_origin", &529034805u32.to_string()),
            attr("relayer_fee", "0"),
            attr("token_fee", "0"),
            attr(
                "timeout_timestamp",
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
            token_factory_addr: None,
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
            denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
            local_asset_info: AssetInfo::Token {
                contract_addr: Addr::unchecked("orai"),
            },
            remote_decimals: 6,
            local_asset_info_decimals: 6,
            opcode,
            token_origin: 529034805,
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
            msg: to_json_binary(&BridgeToTonMsg {
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
                msg: to_json_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: "token_fee_receiver".to_string(),
                    amount: Uint128::from(10u128)
                })
                .unwrap(),
                funds: vec![],
            })),
            SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: "orai".to_string(),
                msg: to_json_binary(&Cw20ExecuteMsg::Transfer {
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
            attr("action", "send_to_ton"),
            attr("opcode_packet", SEND_TO_TON_MAGIC_NUMBER.to_string()),
            attr("local_sender", "sender"),
            attr(
                "remote_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "remote_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "8990"),
            attr("token_origin", &529034805u32.to_string()),
            attr("relayer_fee", "1000"),
            attr("token_fee", "10"),
            attr(
                "timeout_timestamp",
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
            msg: to_json_binary(&BridgeToTonMsg {
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
            msg: to_json_binary(&Cw20ExecuteMsg::Transfer {
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
            attr("action", "send_to_ton"),
            attr("opcode_packet", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
            attr("local_sender", "sender"),
            attr(
                "remote_receiver",
                "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT"
            ),
            attr(
                "remote_denom",
                "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB"
            ),
            attr("local_amount", "9990"),
            attr("token_origin", &529034805u32.to_string()),
            attr("relayer_fee", "0"),
            attr("token_fee", "10"),
            attr(
                "timeout_timestamp",
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
fn test_build_mint_msg_by_token_factory() {
    let MockApp {
        app,
        owner,
        bridge_addr,
        token_factory_addr,
        ..
    } = new_mock_app();
    let receiver = Addr::unchecked("receiver");

    let msg = build_mint_asset_msg(
        Some(token_factory_addr.clone()),
        &Asset {
            amount: Uint128::from(10000u128),
            info: AssetInfo::NativeToken {
                denom: "ton".to_string(),
            },
        },
        receiver.clone().into_string(),
    )
    .unwrap();

    assert_eq!(
        msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_factory_addr.to_string(),
            msg: to_json_binary(&tokenfactory::msg::ExecuteMsg::MintTokens {
                denom: "ton".to_string(),
                amount: Uint128::from(10000u128),
                mint_to_address: receiver.into_string(),
            })
            .unwrap(),
            funds: vec![],
        })
    );
}

#[test]
fn test_build_burn_msg_by_token_factory() {
    let MockApp {
        app,
        owner,
        bridge_addr,
        token_factory_addr,
        ..
    } = new_mock_app();
    let receiver = Addr::unchecked("receiver");

    let msg = build_burn_asset_msg(
        Some(token_factory_addr.clone()),
        &Asset {
            amount: Uint128::from(10000u128),
            info: AssetInfo::NativeToken {
                denom: "ton".to_string(),
            },
        },
        receiver.clone().into_string(),
    )
    .unwrap();

    assert_eq!(
        msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_factory_addr.to_string(),
            msg: to_json_binary(&tokenfactory::msg::ExecuteMsg::BurnTokens {
                denom: "ton".to_string(),
                amount: Uint128::from(10000u128),
                burn_from_address: receiver.into_string(),
            })
            .unwrap(),
            funds: vec![],
        })
    );
}

#[test]
fn test_happy_case_token_factory() {
    // Transaction used for this test case: https://testnet.tonviewer.com/transaction/aec51d2faa4c0889f691bcbd2f69f805986516a378ccae4628eec2b8c17b0198
    // Here I bridge usdt to Oraichain and mint it as token factory token
    let key_block = HexBinary::from_hex("b5ee9c72e202040e0001000069e50000002400cc00f4018a022802c402f60318038803f80444046404a4059605ba05de068a07300768078807c808ba092a094e097209bf0a6a0b100b5d0b680b6e0bbc0c6c0cc00ce40d020d4e0d9a0db80dd60df40e120e300e4e0e6c0e8a0ea80ec60ee40f8c100e1066107810f411121130114e116a1184119e11b811d211ec12061220123a12de136013b213fe140d14d814e614f415021510151e15281574159415a215c015e015fe161c163a16581676169416b216fe1794182a18381846185418621870187e188c189a18a818b618c418d2194a19581966197419821990199e19ac19f81a061a141a221a301a3e1a4c1a5a1a681ab41ac21ad01ade1aec1afa1b081b161b241b321b401b8c1b9a1ba81bb61bc41bd21be01bee1bfc1c0a1c181cce1cdc1cea1cf81d061d141d221d301d7c1dc81de61e331e501e6e1ebb1ed81f251f711f8e1fdb1ff820162063208020cd21192136218321a021be220b2228227522c1236823ea2437248e24db24ec256825b52601261e266b26b726d426f2273f278b27a627c0280d28592872288c28d92925293e295829a529f12a0a2a242a712abd2ad62b7a2bc72c482c952ce62cf52dc02e0d2e1a2e672e742ec12f0d2f1a2f282f752f7f2f882fd430213040304e309b30b8310531243171318e31db31f83245326232af32cc33193336338333a033ed340a345734743492354035ee369c373237c837d637e437f23800380e385b386838b538c2390f391c3969397639c339d03a1d3a2a3a773a843b3b3bb23bff3c0c3c593ca53cb23cff3d0c3d1a3d673d743dc13e0d3e1a3e283e753e823ecf3f84403a4087409440e140ee40fc4149415641a341ef41fc42494256426442b142be430b431843654372442844de459445a245b045fd460a4618466546b146be470b471847264773478047cd47da482748344881488e48db49904a464a544aa14aae4abc4b094b164b634b704bbd4bca4c174c244c324c7f4ccb4cd84d8f4d9c4de94e9e4eeb4ef84f454f524f9f4fac4fba50075053506050ad50ba50c851155161516e522452da52ea539254365442544e54d45594561a562c56d057905817582858cc58d958fa590459125920592e593c5a205b045be85ccc5ce55cfc5d1c5d3c5d795db45dc25dd15e915e9a5f205f3c5fed609060f160fe610c611a616c617a618861da622c623a628c62da6328633463426386639263a063a863b863c463ce63d863e263f0647e64c6655265da65e665f4665466b466c266d066de66ec66fa6704670e6718675c67a067e467f267fc68066810685468ac68b668c568de68f869066914696669b869c669d469de69e869f26aae6ac66ad06ada6af26b166b206b2a6b486b586b666b6e6b7c6b8a6b986ba66bb46bc26bcc6bd66be46bf26c086c166c246c336c406c4e6c5c6c6a6c706c7f6c8c6c936c996c9e6cad6cb36cc06cee6d1c6d2a6d386d466d546d626d6c6d766d806d906dc66e186e266e346e3e6e486ee06f786f826f8c6fe0703470427050705a706470aa70f070fe71087112711c71447192719c71aa71b871c671ce71dc71ea7230727672bc73027348737c738a739874387446745474627470747e748c752c75cc766c770c771a772877c87868790879a879b679c479d279e07a807b207bc07c607c6e7c7c7d1c7dbc7e5c7efc7f307f3e7f4c7f5a7f687f767f847f927fa07fae804e80ee818e822e823c824a82ea838a842a84ca84d884e684f4850285a2864286e287828790879e883e88de897e8a1e8a2c8acc8b6c8c0c8c168c208c348c428c528c628cb48cc28cd08d228d748d828d908d9e8de48df28e388e468e548e628ea88eee8f348f7a8f888f968fdc9022903090769084909290d8911e912c917291b891fe925092a292ae93089316932493329384939293a093ae93bc93ca94109418945e946c947a94c095069514955a95a095e695f496029648968e969c96e296f096fe9744978a97d09816986898ba98c898d698e498f2990099469954996299a699ea99f89a0a9a509a969ada9b1e9b649b729bb89bc69c0c9c529c609c6e9c7c9c8a9cd09cde9d249d6a9db09df69e3c9e829e909e9e9eac9ef29f389f469f8c9fd29fe09fee9ffea00ca050a094a0daa120a12ea13ca14aa158a19ea1e4a22aa270a27ea28ca2d2a2e0a324a368a3aea3f4a402a410a41ea42ca43aa448a456a464a4aaa4f0a4fea544a552a598a5dca620a666a6aca6baa6c8a70ea71ca762a7a8a7b6a7c4a7d2a818a85ea8a4a8eaa930a93ea94ca95aa968a9aea9f4aa02aa48aa8eaad4aae2aaf0ab34ab78abbcac00ac0eac1cac2aac38ac46ac54ac62ac70acb4acf8ad3ead84ad92ada0ade6ae2cae72ae80aec4af08af16af5cafa2afe8aff6b004b012b020b066b074b082b0c8b10cb150b196b1dcb222b232b276b2bab2c8b2d6b2e4b2f2b300b30eb354b362b370b3b6b3fab43eb484b492b4d8b4e6b52ab56eb57cb58ab598b5aab5f0b636b67ab6beb704b712b758b79eb7acb7bab7c8b7d6b7e6b82cb870b8b4b8c2b8d2b918b926b96ab9aeb9f2ba36ba44ba52ba60baa6baecbafabb3ebb82bbc8bc0ebc1cbc2abc38bc46bc54bc9abca8bceebd34bd7abd88bd96bddcbe22be30be3ebe84becabf10bf56bf64bf72bf80bf8ebfd4c01ac060c0a6c0b4c0fac108c14ec194c1a2c1b0c1f6c23cc24ac28ec2d2c2e0c2eec2fcc30ac318c326c36cc37ac3c0c3cec412c456c49cc4e2c528c56ec57cc58ac5d0c5dec5ecc5fac640c686c696c6a4c6e8c72cc772c7b8c7c6c80cc81ac828c86ec8b4c8fac940c94ec95ac964c972ca3cca46ca50cb1acbeccbfbcc08cc90cd16cd9cce6ece7cceb1cebecf46cf54cf62cf70cff6d07cd08ad098d11ed1a4d22ad238d2bed344d3ca041011ef55aafffffffd000100020003000401a09bc7a987000000000601014783930000000000ffffffff000000000000000066a5020d000015f1064cd440000015f1064cd444841393050004795f0147838d01478352c40000000800000000000001ee0005021b3ebf98b74a5680e572023ca9aba0000600070a8a04f827c487ce169f50b3e16a6c31b09a10e77e4664bad817c1093e2e77938f73c4acb9b4709a9b05b3935686d7ff5c6738c9ec6c461b4399a68d0ba8770999b3f701c401c40008000904894a33f6fd2692243c594d47868d2e183fdd4977f2ae87c7dd04d914898766264cb38dde50ac0f460d8e0deacc55106c3fd58c8313995e21c8c13bd4c113b976da00f56180c0001d001e001f00200098000015f1063d92040147839232b4ba5482f27cdb86377fe667add2f0c59965015f974be0a77d6d89c8c43a34b45d995b929b83b4bf9eff3986e2c8b024a973961cc91b4bd630a06550ea56be0225845cb6c401018eb2cc22e5b6205ac07cc1c00801d701d7001d4448d70ae252b4072b91954fc40008245b9023afe2fffffffd00ffffffff0000000000000000014783920000000066a5020a000015f1063d92040147838d60000a000b000c000d245b9023afe2fffffffd00ffffffff0000000000000000014783930000000066a5020d000015f1064cd4440147838d600012001300140015284801012a68ae632a93c55a8c4aed2ecca2867137a25d4438421d8999aeb62d0602566c00012213821172db1004063acb30000e00da22330000000000000000ffffffffffffffff845cb6c401018eb2c82800da001c3455f4ac5b3f07e88a575ebb300bd3af755605319db8fbae62ccefe8768d8bfcba9d92192bf28b16cd06197cfc954fa4cfb1f1bb7fc70ba5aa4984bc5d9aba60501f001b000ecc26aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac231b72e61159df14600450046004700da23130108b96d8802031d6598000f001900da23130108aeeb484f390cffb80010001100da3313887089b5c18971674d46acaab1dfd4605fc9b2dd7583c96936c70bdd7ca92cef611ed5d09851bd8e23ce497d7eb50f7c803645cd357b05efd4b7076774454cd9011000120108a6fb5d4545b6bfb80022002300da321157a1e466530dce40ecbe55c0d443457bc2941cd787f4294100d44fff5b9703426de31562a8a7a60a2a70f207b4b80046dc7b0f0dd0c6acbb75147e3f2889b66a01c0001700e7efeb09f3564008003600bc012f00000000000000006000000000000000008000000000004000162213821172db102d603e60f0001700da22330000000000000000ffffffffffffffff845cb6c40b580f98382800da001c345559ead3b1370dec8e4a9d391c49099e52f3d3af4be3540910eb5c71d2d5f9d65e7b73970ea737b23567f00b7b944c767a0a3019709bd80def5d255021fce6714b001b000fcc26aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac231b72e661d13c946018b00d800d900da006bb0400000000000000000a3c1c980000af8831ec901ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc023130108b96d8816b01f30780018001900da23130108aeeb4863e60eca98001a001b00da284801014bf723fa1d01bcafa4d4c8f37f34da2b43574ca656e53b8184ab475450b28dc001c033135a498365461c12981cd260b0a385ae912a746225a8c0eafe920b76dad3790713d795b058e597547bd287721e7ef04daa77c242fac0eddcb29d43ff1b7c6f7358011000120108a6fb5d59f2b88a980099009a00da32115df7d8b2ac96a9d8f9f3833874331da64b01364c00e65bbea068b85d38fdba57d3fcd9dd06a7fcf8ea92d80a78458add2c99427c7e1fe903053278fd25d32e3b01c0001600e7efeb09f356400800bb00bc2848010161d3908db6a90bd353362bd10d324068153a82c5d179fecfacd3ed27474c338201c00103802000210001021101a4472395075f35afa1cbab734752b26a1c5dfcab9121145b5141c4516c0ef2a1000682017d14573b70170cdf610f2de26a86f49dee4255b44a0fccaad0552dd16f709f7d7c91540013cca5e8891ae15c43b9aca002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac018b018c018d018e0247a01cee2de41a32a70f539f585db935251b0a884ec0dd38fc6726f1690b8c01f881c00610019d019e2313010896d9fdb10886a3780024002500da221100f0215f943d301c48009b00262848010188e41ddf0ab58a1b2b1e756c22a36079c0e69b9c70eda1f85219917c58a571f5001c28480101b213185bcf747448112729388a8b8591d0ed7bc1be376b89bf7d2d26af1a2170010e221100ef74fb5d69effc680027009e221100ef68819f1853d048002800a0221100ef18fec6be2baea800a10029221100ef18fd2f1755e14800a3002a221100ef18fc6ef86a6e68002b00a6221100ef18fc6ef0ff0468002c00a8221100ef18fc6ef0ff046800a9002d221100ef18fc67a141fa6800ab002e221100ef18fc432e65f1a8002f00ae221100ef18fc432e65f1a8003000b0221100ef18fc432e65f1a800b10031219fbc66666666666666666666666666666666666666666666666666666666666660778c7e219732f8d295dfb8f6e5846e4770a2106c61e6d29332564cc0659123336bb74d90db144ef00000af8831ec901400322275cff33333333333333333333333333333333333333333333333333333333333333333c8bb720000000000000057c418f6480dde31f8865ccbe356d000b40033224b62aacd49cbd62e91e79a7a56e6f851db61d64aac381c0cc6137196d2f17b0b9f26126f64426100b6003422058f66a5003500b92173a1cbd6cd4a0b1e000007082e91e79a7a56e6f851db61d64aac381c0cc6137196d2f17b0b9f26126f64426172f1457cdd53ad86078414166f044000ba221100e32a31568d810ae800bd0037221100e2050db0e7986868003800c0221100e1465520b2eef7e800c10039220f00c02e6d39abade8003a00c4220d00b5ab846de2c800c5003b220d00b13474cf6cc8003c00c8220d00b13474cf6cc800c9003d220d00b094f4fbf4c8003e00cc220d00b08ca8e2e2c800cd003f220d00b08ca8e2e2c8004000d0220d00b08ca8e2e2c800d10041220d00b08b0670d988004200d4219bbc6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0584583386cc4f4aad698a53b7c5d6aa167366a00d3be93074faa2d5b27e7cd2f5b67d27eab480000af8831ec901c00432275cff55555555555555555555555555555555555555555555555555555555555555554058cc075d8c000000000000057c418f6481161160ce1b315d000d600442149000000e133c0b9e075702d034da2231b6f08fec709b28c6821270413d2cdb6e890a186b640004628480101b96df870a6364fae8bb77286e253613c71241c81c945798ab98e5fd9cba60afd0004220120004800dc22bf00019121f1910004795f600002be20c3e1b0880000af8811f9da380a3c1a96e6e24f307e88f6265c58996b6c9fb7fc08e776b8f38ba6fdf418d773923b3a95c3566c3a3be21d67e7c854479974120682c0b01d148f25847fb3762a0774ffd8be004f00502202d8004900de22012000df004a220148004b00e2220120004c004d220120004e00e32101d400e628480101401a8de89d561281a5c83335e49df521755480906352aec0481c81dec2b8e2be00072213c3c000057c4187c3612000e90051220120005b005c2211480000af8830f86c2400eb005222137080000af8830f86c24000ed00532211200002be20c3e1b09000ef00542211200002be20c3e1b09000f100552211200002be20c3e1b09000f300562212cb000015f1061f0d8400f500572211200002be20c3e1b09000f700582211200002be20c3e1b09000f9005922116000002be20c3e1b0900fb005a2848010164dd235e9b7c6ffcc729406358a5293f14a4933b0d02b1bd630719de292cc895000132013527d0e0616e1f6575f58ca813a58e414123aceb4740ec0e6f721a10f313f3c2b3b63bc48a6515ea8ca9d9f9cb88f089ce0cebe4386f890376a0faf5dfec72910010000b20005d005e3201eb7afc30868df0d34d007e4acdffd548dfcaf6c830147b38ff182dfcac05b70b7394598d3e19334eb824550d18cba1c2b86d175fa24b076ab126f22a9e8cd95e000f000b20007b007c220120005f0060220120012b007222012000610108220120006a011a2201200062010a2201200063010c2201200064010e22012000650110220120006601122201200067011422012000680116220120006901180073de88cd4a041400000000028f071e000005cca68f68280000bb1ef3d270d8cd4a0414000000000479c2820000130999c677f00003280e23a79fd1220120011b006b220120011d006c220120006d0120220120006e01222201200123006f220120007001262201200071012828480101448c582e8e90a038dfb093cd962694f1e525267e0dd7badd50f8afd70f10a10a0001220120012d007322012000740130220120007501322201200133007622012001350077220120007801382201200079013a220120007a013c2848010107d84954c4845aca7eef74911f6fb8045ad1ce71bd2b2947a441128e22d8929d00022201200143007d22012000860158220120007e01462201200147007f220120014900802201200081014c2201200082014e220120008301502201200084015222012000850154284801019df5a6141ca07b869942d28087f5892353d38a13ecb923b963af29298f6cc137000122012000870088220120015b0089220120016b0091220120015d008a220120015f008b2201200161008c220120008d01642201200165008e2201200167008f2201200169009000b1bd1c9b66d873b017caf3446e36bcb77c3d14bf1ab8b0794cf4ab34991faf31b119a9407a4000000000000026c000000b14b2a25d80000024c2413b2c19a9408280000000000000b0c00000281f28be80c00000a64fd7b6b8a0220120016d0092220120016f0093220120009401722201200173009522012001750096220120009701782201200179009828480101f423b86e5689a5bf0ec4fe5255a6aadda7f753bc2723c11e5ab107d600aea17a00012848010119048a015da367b0857e23ea45bfa8debe8107ff4731dcef81a5cd0f608b22c3010f221100f0215fa8ea31e728009b009c28480101802ef4b3aaba6da0765e77c7e4f5285ec80e4a9a49c529702ce11b5e9edd7987010d221100ef74fb7216f1c748009d009e221100ef6881b3c5559b28009f00a0284801010293d17b7aaff7d5980ebcae8b8cccda58c7cb6d5dab78e2cc9231eaf2c79cfa001c221100ef18fedb6b2d798800a100a2284801018299ecd271b0e966084b793f24ebbaab6fc6cc609852ca2640b431cfa53c37e7001b28480101ee1e3344e96554362585ec8b57672265fa2b51e1fed60580b3c9586a378b1bd00018221100ef18fd43c457ac2800a300a428480101a83901cbde7b5800b74328d91cbde0a7c05c4046253516bf6708640b92d4cf3f0018221100ef18fc83a56c394800a500a6221100ef18fc839e00cf4800a700a828480101cf0656dc2cee681c476545f4134bd254c3a8a48d05886918445425c1ccd8e5610010221100ef18fc839e00cf4800a900aa28480101c5c880016e9935e5a9d13625ab55906595b1b18e10af95ae7b5acebf074cfd35000e28480101f0100886305f3f4ff7ea1c75ca9bf9ecf18b387ea4438a6725028a8f82da0723000e221100ef18fc7c4e43c54800ab00ac28480101926a952a8ef37ba5605f80d0e8af5080cc4f7e42551634b5cc80fde262c88acd000e221100ef18fc57db67bc8800ad00ae221100ef18fc57db67bc8800af00b0284801011e39176f9c47d86a7093cc4d56ebeec466860b47b831e031eced9694f184d287000d221100ef18fc57db67bc8800b100b2284801016cc174ed2e12538f670df40eb19faed1664f49d64c6f317e481b3ee9a4b51f96000728480101a4f536d1598c09f2ee6454cc13c126e4707c33e9f865659dc51315c26785543f0008219fbc66666666666666666666666666666666666666666666666666666666666660778c7e2bedb3de44c294c51d41e58b221ef432150912ae0a9052e82e6c4144b1f5e20b8337dbab080000af883266a21400b32275cff33333333333333333333333333333333333333333333333333333333333333333c8bb720000000000000057c41933510dde31f8afb6cf7916d000b400b5284801016217f872c99fafcb870f2c11a362f59339be95095f70d00b9cff2f6dcd69d3dd000e224b62aacd49cbd62e91e79a7a56e6f851db61d64aac381c0cc6137196d2f17b0b9f26126f64426100b600b728480101bdfc09c72cf45850fc6b183f5770814a186ab44c2e7e86bc0e035eaddfde51d5000822058f66a500b800b92173a1cbd6cd4a0b1e000007082e91e79a7a56e6f851db61d64aac381c0cc6137196d2f17b0b9f26126f64426172f1457cdd53ad860784b97e7d5b4000ba28480101346e5a1d657fa0fed03aa894f95740e944ba3b887be114ac761efa47052eeb8000072848010136de2d205dff9cf62cc312c0c96c1e911ee0561ab93df1a342fa65ffb9b4fb9a0006221100e32a31568d810ae800bd00be284801014b4c061d2b57cd65f942471d856e391b0196c63ce9238cef7d10fca02e80054f010f28480101f44667a9249922d16195acf3a144f4389a5b85ebcff64f0a2a2280a930bfefb401be221100e2050db0e798686800bf00c0221100e1465520b2eef7e800c100c22848010105ba92451ec1aa473812d1dc755fb61873ed02d9f15482768ce82c8cdefd3a8a001d28480101938360663de65ed3984b0519379a6ca6ef72e561414eb88c7256ba3c85249c50001a220f00c02e6d39abade800c300c4220d00b5ab846de2c800c500c6284801018254c8e5828513d12b6d96ba0b08a900f708e98ad582c7c2bc5b3401458353d10013284801016130ccaea62f13cb1db304501ce904bb563d50b5f37cd38b3720569a728c14960013220d00b13474cf6cc800c700c8220d00b13474cf6cc800c900ca284801014b38c73d835f32ad6a8e0475001c29db90098399eb740a71b012be2761c728b5001128480101559a27230589c27e4abf4f06069c659f9f5936f8feaf346af898dc4b6902f68e0014220d00b094f4fbf4c800cb00cc220d00b08ca8e2e2c800cd00ce28480101620df7f2d05018a08f4be309fa72bf18a186e7750b126e067c2cd298c4a4e5d8000f28480101d80fe5059dba6f072508bee4ab0154cd81d7182bdcec18881e4eff9ef812d9ee000a220d00b08ca8e2e2c800cf00d0220d00b08ca8e2e2c800d100d228480101479c52bbcf4e8bf474e96b9ddc6d8e9ccded84204c1e59ab1686d8157f134faa0008284801010fda15785477e78cbd077f2a3a66e7e60ac693c75e93dcd531e1fb53f7b877f7000d220d00b08b0670d98800d300d4219bbc6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0584583386cc6980634b0936978ad23163e97e24c07db6f30b16c508c8fed9e7a8f5a8c22dac80000af883266a21c00d52848010115e7ab7c473765098c388f207811984b0c38d1491485440381c1b14ce666d42c00092275cff555555555555555555555555555555555555555555555555555555555555555540534c068f40000000000000057c41933511161160ce1b315d000d600d728480101a794a8332a9f63bc7f7859f1df063cfac970fd5d3523017747ad95d248e376d7000c2149000000e133c0b9e075702d034da2231b6f08fec709b28c6821270413d2cdb6e890a186b64000d822012000db00dc22bf0001082b4f4900047960e00002be20c7b240980000af8811f9da380a3c1a96e6e24f307e88f6265c58996b6c9fb7fc08e776b8f38ba6fdf418d773923b3a95c3566c3a3be21d67e7c854479974120682c0b01d148f25847fb3762a0774ffd8be00e700e828480101b20e36a3b36a4cdee601106c642e90718b0a58daf200753dbb3189f956b494b600012202d800dd00de284801017c9d19cab6766def0144f765cdec3f06281ce53e037ad8cbec80a24fea291105000722012000df00e028480101c614d3ed01424d9df69104c0e9dae3f1b94fe097329e0fa1c707c09c8eef8f530009284801012b9eeb4530032bfe76282926ff07b33bd90245548963411faf0a4b58dd44c4b5000d22014800e100e222014800e300e4284801012c60df2ad5c564c1a5717b0396ed695c0eb00c33130a12736650261f7cd3ec15000e21014800e521014800e6284801011748f3cd3d2b737c28edb0eb25561c0e066309b8cb6978bd85cf930937b22130000628480101f4b64879a0af502d3e255056e89f1a35f94445cf03e2a17126362c08a2c5721a00062213c3c000057c418f64812000e900ea22012001010102284801017e609b403aa714099b35c622bcdc49682b7ee3ad60c1421f355f6c3e9832580c00182211480000af8831ec902400eb00ec28480101dd328edbc3351e367b8664b0565ed13da843c1ce7094d46ff5c4555716be5bd9001622137080000af8831ec9024000ed00ee28480101a93e18a559eff957c4ebb18b453cae25d1e19861332c2f88a3965a233e99299a00122211200002be20c7b2409000ef00f02848010127d7cc7c07c280e660758e96ddee56e513b989844adc87d9075f20fd5d867aba00112211200002be20c7b2409000f100f2284801015d6c85096c64d0f3de4ef47f7d0c2b9dc87e21e1208aaf1538a4c7290b0d699b00102211200002be20c7b2409000f300f42848010117880f1ba7fcc30cf501608d19b4d48a3bc0ba01f03918b5b49652d2cae949ed000f2212cb000015f1063d920400f500f62848010131d4c296cda05912f73b7acd441de26e06aeb8c615e075750b7d052b5ab4d11200092211200002be20c7b2409000f700f828480101c650658696e8d40017ddf41974604bddd0b3e7186fec968510d6d37da85b137800082211200002be20c7b2409000f900fa28480101aef7a0b48c9887a731c84e37e6d9a0591ec6111286b0b4f75ff0bf5c9dfd8403000722116000002be20c7b240900fb00fc2848010189791325b2cc4dc50cc009521d3e91735ab9d5745cec3a2bdad059abf986ffce000402116000002be20c7b240900fd00fe0211000002be20c3e1b09000ff010000a9400000af8831ec9020000057c418f64810051e0e48cad2e9520bc9f36e18ddff999eb74bc3166594057e5d2f829df5b6272310e8d2d176656e4a6e0ed2fe7bfce61b8b22c092a5ce5873246d2f58c2819543a95afa00a9000002be20c1f9688000015f1060fcb440147839005390f02e1b624ac674364ec91c2b51b590267cbfb4f7aa32a56a88763e4188b4decc1deca12eee5f1f15e076c99cd93c55909fa3a57a05989944f09be0988fd800a9000002be20c3e1b08000015f1061f0d8401478391048a2f54cca2e056537bab7c380679000371101b7dc24b4c9c91ab65bc41d2d000f0d90c4298beef3aab302b304fc77d02ecb6d7c25e9f9ddd49f711841d8f2f83201c2e4b0a60f67e35e10a47e07ff0dd75d4875941b629276c1f24169647d53442e085d87db4265e3f9195b6f0400553242600db65c8138897de76f6842eb5ca89b0010000c20010301043201a7db215b7de6d94b2111742de33072dbcdeeedb6d8e93cf37762575c07a526a4243021a0b40ac87462ae7f51d9d49cfa083f9c05215b06d11c42d59b71c8eea0000f000c200141014222012001050106220120012b012c220120010701082201200119011a2201200109010a2848010182c10743729b8b38256b9a0e23860fdf3645f7a628c4c1d81736b26febf0fb4a000b220120010b010c28480101df88bd43f622ad0f376e80e0d1e62501027af4dd75333cd4ec92bd7ceca8264d000a220120010d010e284801011e1fbbe4b410dec089f0853f89c318a6dda8590af38298cfec6f669545f1be860009220120010f01102848010167e262d4e7174968556fa157111b1afbb4393b97be4445f92c70ee9a72e6f41000072201200111011228480101fb5e9149762bbd11bf9dbe43c40acd84f2c8f45ee19845404fcc9b16cba8abec000522012001130114284801013df25727d155fb237972855712fa19cf18ca5738e68100c268ba69d203d4838f00052201200115011628480101c1683427e025e1fa4266367aebbd5094e7c56d023cba1cd12ae475539e61fdae00022201200117011800b1bd7de728361b0f10dd102f5a3490ba3438b749b3ae9f3c347995a7a889331aa48cd3756a8000000000000011200000049b16862ca000001039591cececd3756ce0000000000000626000001af5bd0d28e000005d23c0c817100073de88cd4a041a00000000028f0720000005cc7a39490c0000bb1ec278df68cd4a041a000000000479c28a0000130a77834f820003280cab8b690b28480101c13377c493d48ec11fb6dbe9c1ef11ce9cf651e8a90a48e0925524c9ffce04d00001220120011b011c2848010166f6ef892bb70434862f270310b5d480bd0f79cdc69fde4b2786c9a19b0491db000c2848010177c4e3bdaa9b05ecc061499ab78465ffe8725560a61c0bc0b35e988d1ec5444b000a220120011d011e284801011243df1f970d8f1c380187d18498f0cd9e7585fe0caff310068769c17c67e4ac000a220120011f012022012001210122284801018f39e9cf4ae485873c27e65fb810c339020d611ba3de2bb08c9e44eb7a44377e0007220120012301242848010152a610477dda63dbac2e978581db0da7b6a51f2e83ffbe80711f91b7098aef80000528480101c02acf0f9a812daba46ac93f42b611d8a0d7c395c856842462c9bc143fde7d8d00032201200125012622012001270128284801010baec90da4d4ed30e6ac30bd1930eb02dce85f6f5dd7344a2b484f75d418780400030201200129012a28480101970a08d0970b73954098b9ca1da3e234a5d6ff2c2ea41da16b518ba4db4cdf82000300b1bd096007ed38ba9ba7eea16ba28f5aaba86012e95d7e309002b202cb6a106d2d19a39f12c0000000000000244000000a8471402fc000002268f821cb59a39ee7800000000000004340000016418b195ec000004018f5a2ff6000b1bd22b611dd8e0c2e22ee4aae2bd8485e79ea4a8cacdc966798323786824c55c919a9408040000000000000258000000ab1c79166400000238f5e6f96d9a9408340000000000000b18000002b073d3180000000a74b319ec6a028480101cce2e62bfd578f8ac933f81a401b818e509d1f49e79694a35fdffc3614107a21000d220120012d012e2848010119fcfe6655ca440f735c7f562d430d4090f87006307bc03d4b36c68b5059d4a6000d220120012f01302201200131013228480101bc47d3272f6786fd12622a0ac986b0d33892c12c7d0e7a97da7ef6b5de94358800092201200133013428480101920d40cec7834f8d0e27cc78d4f19890585aa1b1fd58387a8d06255756b09b23000828480101d05ce9303e8cb8e3b7529fc79f3685b865574a1839da12373c61aced78872a420008220120013501362848010149f6e21d8b8c44ebb172043c572fefe7fdab03e80a9b10131840a040c999beb80005220120013701382201200139013a2848010165a031f240e98426ef24320d7b226e14e2b57e465767fc28b9bfb8226ff716be0004220120013b013c28480101a726d497e7085910530f5a9c78d666b4a5823fe870af2365dfc2d378f48ea94b0004020120013d013e284801015d8e8da9892910af9773a0b972d12bb08f36c7eb5a9685e02436e276bf01cc9e0002020120013f014000b1bd1785c43463950393b6d53b7ce78e3c187cc8d73692efce933e9146d3100ea119a528d1c0000000000000288000000b2be236fe4000002661d9cb1b59a528d9c0000000000000c800000035b495bf7d000000bd3f9accfc6000b1bcea59ead12dc2ac505c4c9106accbdba6996b6240eefab132449011d5876c4a335272d780000000000000408000000ff0c0c4880000003ce0a6d6a7335272f080000000000001810000007610614c088000016d7a91a20ac000b1bcec175c1970b4c9870d3d92c8c1eb291a2dd0bd06440de8a510c8a5c274964a335280f7000000000000004a00000016104b09240000004662221ba933528106800000000000014b0000004f2c2d1eec0000013821652e79c02201200143014422012001570158284801018fd4726d3b449611333181a3b5a1336ef704428b2228b93ef551144ef676ed26000c2201200145014622012001470148284801010fb0163452204229b95dee1d6dd2a580ecc4b93194146bfa6a55cad4f7f5a4ed000b284801012ae550fd59a7107b60d1f20392263b1e73a8968c394805ce9dc1f68094069ab1000a2201200149014a28480101936d741df8854d94efbf978c6316252c0251bc1ded784a27e19501d37b3ee8550009220120014b014c220120014d014e28480101fa3d8ba0658b11aed8c6d6709057f0053f9fdc20b37c5139e846d4194ecb80a50007220120014f01502848010123654f87ccfa4768b4d8b1aaa9b147abf4c7e03719c51c5931ab07c2b86bc50e000622012001510152284801018edd5890808f93583a0da0cfca3b7e7b1d8364aab37b11c3a544c619776641ed00052201200153015428480101f4c0bc47ab2dec074329a0a2e755bd7afc07520d5895f3dfb1d2e98692e6615d0003020120015501562848010161d7c3cc86574aca1fae5676c83d83ebf71858324ae4d9714c70974469868519000300b1bd3d18363837ab315441b0ff56320c4e6578872304ef53044ee5db6803d5860119a9408340000000000000268000000bb2bf8e760000002492165e3199a9407a40000000000000354000000ebe065494400000328a20bec42000b1bd21d29318c6f775f53306d2d2a94c79931b32c74b952d7bd33c148c400a217519a673508000000000000024c0000009e94ac7cdc0000022caf6674959a6735240000000000000c8400000381ae8a24c400000bdb1c57c53202201200159015a28480101bac623f5d156058b86d19264828bb9308cd778a4b2308d1853be4fa0f3902e99000c220120015b015c220120016b016c28480101b42d13aa3ac39f0d3d7e42b423e0dda5a9fb42412e8d5ec2b7938069a35203b7000b220120015d015e28480101428cb54b0596ee06299bc6de6cd97af0f901c9fdf582a5b90c388214612f12310008220120015f0160284801016f3978065e721bef61de0c390609b2cc5cf6e98423c75edc4b0d9006adeec549000822012001610162284801010ae21be7ff75919f65ad006e779e06571e4acbbaeaddf6b8effa991fd615e6e20006220120016301642201200165016628480101c7b7c45d98314737d1a75f59e8cbcd225f9fa23a340f635dfe54ec467e396c1d000428480101fab26922a511c8e2489d7f64f9fef3a7722649815f817db57b4fe39f99304b2100032201200167016800b1bd5ad9959703abc92e442c3f6f1bb6aa4704c334a6efaf1e21ecc1344023ad768cd16d17c00000000000001240000004f368a427a000001145c423484cd16d1d8000000000000064e000001c6078fc32a000005f9d66298d902201200169016a2848010181ba445f4ed37d8a8e666194ae536a37aaf86c36a7b58182817b21c026659167000300b1bd1c9b66d873b017caf3446e36bcb77c3d14bf1ab8b0794cf4ab34991faf31b119a9407a4000000000000026c000000b14b2a25d80000024c2413b2c19a9408340000000000000b100000028501fe110000000a68de4ca1de02848010187e0961a723e683032353871bfec83ab30fd105b4be40557c1da7d41a83075a60009220120016d016e284801015ea2805328eb609dcbf356dce4123654e47b0d4da48581dda7516edaf6d2243a0008220120016f01702848010188954fa8701f34d1d983f5536470417bfbef1509d551177f411e4549776eca950007220120017101722201200173017428480101dbffbfa7741a171b0700640f8157f126e1c81642fd644601c54a94148373a7320005284801019f9b7c9101653271ac8a69c26d348d36a6f030b5b784026ac5572e82b18a71c40004220120017501762848010135577bfabde8269b18ecde490e2f044c393cbb5476b27dabf8ebdc78aff44aa70001220120017701782201200179017a28480101b8b63d665ae27e416897e7147b9792aec88c1029bad6bd9ab3f2d0fe4afaa279000228480101dd0fff1f6c74569acbb86ddecade275231705b46722b91dde82cfe0d59c0772a0002020120017b017c00b1bcd7b5965b82cbf2cbc1ebd8ba84fe7c66976745a5ce337b051172a3f7e9efba3349c500800000000000004a00000013cb97704a000000461d604331b349c51400000000000001900000006f78ddb8480000017ae14fbbf64000b1bcdef85a8997ccfb95292cc3256651d56eee4e7862fea8da805a8aacc37db0da33528101800000000000004c800000177d96131a80000048c68ba32cb3528106800000000000015b80000052ddae19138000014788729349c002034040017e017f0397bfb333333333333333333333333333333333333333333333333333333333333333029999999999999999999999999999999999999999999999999999999999999999cf8000057c41933510040180018101820297bf955555555555555555555555555555555555555555555555555555555555555502aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad00000057c41933510c10187018801035040018301034040019e0082726a2342148ff95294a2da4a7001ea1ef98bbdfbf114e62e675bd61c91d611bb354e6406ef1c8164a970ff64a5e57d14f5415014a5661be43f850b328c642a0e1203af73333333333333333333333333333333333333333333333333333333333333333000015f1064cd44152bbf71edcb08dc8ee14420d8c3cda52664ac9980cb224666d76e9b21b6289de000015f1063d920266a5020d00014080208018401850082726a2342148ff95294a2da4a7001ea1ef98bbdfbf114e62e675bd61c91d611bb357a78f8f88811798df1f83ca239331125a530d9451dbf684b03343653de9936cc0205203024018601a400a043019008583b000000000000000000880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003af75555555555555555555555555555555555555555555555555555555555555555000015f1064cd4439e955ad314a76f8bad542ce6cd401a77d260e9f545ab64fcf9a5eb6cfa4fd569000015f1063d920366a5020d00014080208018801890082728e398edab171ce0492151f59c1c6ea5725b2028d1ebe9963769399e5f0c8c932affe519a378863f393504a382fd90ed48013aaf86dfa6fb389ac731fad8751170205303024018a01a400a046f05008583b00000000000000000044000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000103d040018f0215c8111235c2b8877359400801980199010150019c02012001a501a60201c0019001910201c0019201930201c00194019501db500afbe5200a3c1c980000af8831ec90000000af8831ec900f4f2d7713b140314e27ed25e519fc4358bfc1e914a69465ca9f3f66d10aeace60a6c7e359c30a616dfcafcb8348e0bd4b70d98cbf31773f8c4a1a2b3b65512858800023da1100000000000000000a3c1c8b35281052019601db500afc18080a3c1c980000af8831727e000000af8831727e08f9419b677eb07340e4c0ca75f68b07beba94dd96b55efea686e7964e172fb61482d87413162b678f57dba28478afacbbca6d4b92c1c7a5cf3968c044f13f3fc8000023d98300000000000000000a3c1c6b3528104a019601db500afb9cf00a3c1c980000af8831727e000000af8831727e0c05a8ec7036ab7dfef46b9b585d0fafdca02dc754f18b8f00f387963b0b6c9c7cdcddc20f37cce928407938cd006087ef4dfbc4753a73e40b29dfa74f65b7e6a0000023d9bd00000000000000000a3c1c8335281052019601db500af77e380a3c1c980000af8831727e000000af8831727f5a6c210bd459271a2914fdcf2699a551d32c5db3a766456eac210c61847e0f94441c99a8ed970414c8525ba951fd9d747c633c4e3c6e98657b27da2e185f5e76a0000023d9df00000000000000000a3c1c8b352810520197001340ee6b280207735940200013417d9592e207735940200213107735940083b9aca008019a019a0213109b002eb883b9aca008019a019b0037be800000000000000103b9aca0081dcd650040ee6b280207735940200037be800000000000000105f6564b881dcd6500417d9592e20773594020020161019d019e010646060001a203af73333333333333333333333333333333333333333333333333333333333333333000015f1064cd44224fc3d808efb902094ec5a260ef5fae5ab205136957c052f0f98f7e1a13f4543000015f1064cd44166a5020d0001408019f01a001a10101a001a20082727a78f8f88811798df1f83ca239331125a530d9451dbf684b03343653de9936cc4e6406ef1c8164a970ff64a5e57d14f5415014a5661be43f850b328c642a0e12020f0409295a0395d81101a301a400ab69fe00000000000000000000000000000000000000000000000000000000000000013fccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd295a0395c0000002be20c99a880cd4a041a4000a042af7008583b0000000000000000006400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005bc00000000000000000000000012d452da449e50b8cf7dd27861f146122afe1b546bb8b70fc8216f0c614139f8e040202d801a701a80202f501b101b202012001a901aa1201c614d3ed01424d9df69104c0e9dae3f1b94fe097329e0fa1c707c09c8eef8f5300094803ed03ee02012001ab01ac02014801ad01ae12010d49449cf7509884fb5260e308166b16af29c6b4dd2bf9abc65f05bc1314f2c4000c2001c501c612011924edcbe515b615a817032ae81d3c3fd9dfdd39a0fc2ae081b125925a5d6169000920020c020d02014801af01b012012c60df2ad5c564c1a5717b0396ed695c0eb00c33130a12736650261f7cd3ec15000e6a028102821101d1e588d4308717e0e0955df9dc9bd8a85af54a852b06a22ca404ea518996d637000748023911011325de76e0adc3221d1d7d649a804a518efd3e436b54d3ee1f369b2f0a6832d2000748025b0103a43301b302015801b401b5004033c0b9e075702d034da2231b6f08fec709b28c6821270413d2cdb6e890a186b60103bf7801b602012001b701b8000400000203ae2001b901ba0103b2f001c101012001bb01012001bf0101c001bc02016a01bd01be0089bf573195a37f3bcfc37b061747f752c11cc32104bbbb9efdb58f0a3dc2d4d25d0201001bc8d1a14b9f0d906d982330f08b45db511f1854ca29d0b9d83ab1d8a8848c20c0200043bf68278ee8eafcc90cee7057ad0b404484c81708df3b9248ab45408973864f3ab4030183e99b81baeb655634a8458bf07c45fa0633cbdb798cb3b9d3e4242760d66d61478f441ac394cf94d0d83a763403654d7809d2f5b67df16f17ec54ef815a92b659800401c00083a009888e4c7d139c821ad2848a8e44f70ac807354535232ff9138ef6a2bb4035e0800000000000000000000000113a25d7619b967fc0008b93b2fb157f8bed892fd00103a06001c202012001c301c4005babe000000000071afd498d000011e0ee9757dabfd1d9f3ef77f7f22c2c6678e84e61dea8d1d77c88ac1f2671f6c1005babffffffffc0071afd498d000011e0ee9757dabfd1d9f3ef77f7f22c2c6678e84e61dea8d1d77c88ac1f2671f6c102012001c701c802012001da01db02012001c901ca02012001d001d102012001cb01cc01014801cf01012001cd01012001ce00405555555555555555555555555555555555555555555555555555555555555555004033333333333333333333333333333333333333333333333333333333333333330040010101010101010101010101010101010101010101010101010101010101010102012001d201d301015801d601012001d401012001d50040efe71d13860afaa6aeaeaf636f9168487f80f1031b0bf8d939ae49d3ea7f7da0005301ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000080000001400101c001d702012001d801d90015be000003bcb3670dc155500015bfffffffbcbd1a94a2001002012001dc01dd02012001de01df120192d187c627f31fe939ad5b722b26c77ef0fef309ad5eac437652968521b9ca2600082001e901ea1201b3ec7acf0c16c7e6d4685968fa2b62d7f87b2fd0ebf8712c5b16d8ff9914784600092001f501f602012001e001e102012001e501e601012001e201012001e40101c001e300b7d0532ee74ecf00010270002ad89fb6870e861a64e10b07b7c8c7496c15fceee7c6f17264a51fef9ce8aa237705f6ff25993b0fd9af4f0ec40c753906568d073da6976b39e24473974881a1000000000ffffffff8000000000000000400131a43b9aca00101201f4801012001e701012001e800146b46553f10043b9aca00002000001c2000000960000000b40000038401012001eb01012001ec001ac40000000800000000000001ee0203cd4001ed01ee02012001fc01ef0003a8a002012001f001f102012001f201f302012001f4020402012002020205020120020202020201480208020801012001f7010120020902012001f801f90202d901fa01fb0209b7fffff0600206020702012001fc01fd02016202030204020120020701fe0201ce0208020802012001ff0200020120020102050201200205020200015802012002080208020120020502050001d40001480001fc0201d402080208000120020291020a020b002a3602060205000f42400098968000000001000001f4002a3604070305004c4b4001312d0000000002000003e8020120020e020f02012002210222020120021002110201200217021802012002120213010148021601012002140101200215000c001e001e00030031609184e72a000711c37937e080006b5e620f48000001e00008004dd06600000000000000000000000080000000000000fa00000000000001f4000000000003d090400201200219021a020120021d021e010120021b010120021c0094d1000000000000006400000000000f4240de000000002710000000000000000f42400000000002160ec0000000000000271000000000002625a00000000005f5e100000000003b9aca000094d100000000000000640000000000009c40de000000000190000000000000000f424000000000000f4240000000000000271000000000009896800000000005f5e100000000003b9aca00010120021f010120022000505dc3000200000008000000100000c300004e20000186a0000249f0c3000003e8000013880000271000505dc3000200000008000000100000c3001e84800098968001312d00c30000006400001388000027100201480223022402012002270228010120022501012002260042ea000000000098968000000000271000000000000f4240000000018000555555550042ea0000000000061a800000000001900000000000009c40000000018000555555550201200229022a010158022d010120022b010120022c0024c201000000fa000000fa000003e80000000f004ad90103000007d000003e8000000003000000080000000400200000002000000004000027100101c0022e020120022f02300201480231023202016a023702380003dfb002015802330234020120023502360041bedcddfe856a99c5cb80784199c0770bea31f28e0d7338f73784480def44cd90140041beb3333333333333333333333333333333333333333333333333333333333333380041beb5679d7b9aa905754ecdaabd4afa6a069c334c9d3aec7934d6b599c53e7043b80041bf1a6267b530e89317e12c61758d1bcc182f096afd95e647a8363e049768f3847a0041bf34931287cae23e2dc14d44ed731b168c6f112ca9cb72d36300ce2bc3c34dfb16012b1266a4e5eb66a5020b001100110ffffffffffffffcc0023a0202cb023b023c020120023d023e009bd1ce3a049e2ab03d18363837ab315441b0ff56320c4e6578872304ef53044ee5db6803d58600003e14b493dab162841b6641c98f1e53a6b54e9a2de67e1c163bfe35ba00ccf6e9c35cca663222e2020120023f0240020120024d024e02012002410242020120024702480201200243024402012002450246009b1ce3a049e2bf4bea08f10ba6406f6b5f42b12f547d3381fbf98f0015af1d5d8ef08774ef01404d45f296b16075d8f6144a1d0c70eca3b0b2fca6b72c17944d69bfbb8cb37fe5b3a67b5afdf1cf20009b1ce3a049e2a37f85f542c6622af876a973484a61fb298b86bb44687aeb2759832d616440ca804d45f296b16075d03de13a2698f313090f2369af08cd6c0d3727cbde9fd9d859d837014269b2c020009b1ce3a049e2b3ddc9b66d873b017caf3446e36bcb77c3d14bf1ab8b0794cf4ab34991faf31b004d45f296b16075ea4f9403c4cd162e112aab43be9570a12c15fd557f5bd828281926023a09cd31e0009b1ce3a049e295224c878e5624ca66444df7e79fe0f50495b9811426da17dda658e8a98498e8404d45f296b16075cdea96a7b8ea2063ee0989cf652950d5f32e492e1ed6017f8bdb88783f061243600201200249024a020120024b024c009b1ce3a049e28b262b611dd8e0c2e22ee4aae2bd8485e79ea4a8cacdc966798323786824c55c804d45f296b16075c9560074888088655edfa55324239a775de74b5e99e20b05ded62708e358178820009b1ce3a049e2b7b6f7c2d44cbe67dca94966192b328eab777273c317f546d402d455661bed86c04d45f296b16075f629693c72a6600b4e8a0298617f313755c7905ada6900611bc9b934eacccef4a0009b1ce3a049e2b389dc67caf818b0a1284494ab4c40ab1a7b46e43cfb01da3bb97e58c1f55abb804d45f296b16075cb7f9a4eed3845db2945aea88cffd4d96263db2628d1c54229b26fbf565ee75320009b1ce3a049e28e7e88e6b8fb043b288e109ab98e225381c04d22bf8bdcef2f8bb974832309b3004d45f296b16075e9ba8a40bb573c891a60368abeea41f043b11435a9b8c689255a9a7e3c38878b20020120024f0250020120025502560201200251025202012002530254009b1ce3a049e2a4b6d304255dba8f74385a578e3580238ea4a12d9726e7d8a97b018c71568b17404d45f296b16075de5264d082c6dcb1bdcec9b15dffabd8e4dacaaafd15228b06df4b240a30f9a060009b1ce3a049e2b59146dc9302d4741dc51f839186e301416237c646f884d4e2d0add4abd7f3e3004d45f296b16075c5473740332a70e928b5f93fb4e76b2fce81ce2bc5ea24b3fca15376968449c620009b1ce3a049e2b6dec4e1bf1415e88fc9a24b7560c296e6818e4f00a75d10d10ab808cb671011804d45f296b16075e60d6efe58def44a942c7d7e437ad38314ea56eb38c2071edc0dfe84fab122a4a0009b1ce3a049e29cc360bae0cb85a64c3869ec96460f5948d16e85e832206f452886452e13a4b2404d45f296b16075c7e12aa909b2a413abfad23c9ac0e1187d55890e01e0e640da2cc5aaee4590cba0020120025702580201200259025a009b1ce3a049e2aa3d91ea1149cd409bf71cb82657285a259e7c0e1300762090a58d930d27b94700459dccc9178dcf2632154ae74d72cbf208021b88ec8d3d89a3fcc246e6532354b918b784c81030a0009b1ce3a049e2b909d952a3d686233ea78bcbd61c1f45436561833364f164586ac1eecc27281dc00a9b637a42745467db40f336fa9b9b7ae76d2a28b9812759ca39292db67f6e816bdcb1f7380f77e0009b1ce3a049e2a823fb5ae650726953d5118bee1e192aaf84b8440d53470be5ecb914208274334008aa8ead2b5d19474d6367ce14cbc71ca90f74325ead8f94b0d78c0e2b4e7976cdac6123f2e77da0009b1ce3a049e2bf9440d6e6335664949ce94ffd5d1f279c06c5bc5d07d9804c2e5cd735041ebac003f396b5ec70278b524493cdc08f0ba0b9606455926f993c9858533b8f075fa19d8a642b239392e0012b1266a5020b66a51e2b001300130ffffffffffffff0c0025c0202cb025d025e020120025f0260020162027d027e02012002610262020120026f0270020120026302640201200269026a0201200265026602012002670268009b1ce3a049e2b87b97f8fa7629192abb6fce25b50384ed85bf01d844fa109dd6c392ce55af4fc04b6ec9430e70ff98f6144a1d0c70eca3b0b2fca6b72c17944d69bfbb8cb37fe5b3a67b5afdf1cf20009b1ce3a049e28700687da1de76f9a3507742c551387a9f9bd04602fa0e5eeb597fe331904f6d404b6ec9430e70ff903de13a2698f313090f2369af08cd6c0d3727cbde9fd9d859d837014269b2c020009b1ce3a049e2bfef744afd2be79a543f76e747bad92c2ff8259244f3500130f24451ad9d230b404b6ec9430e70ff87e12aa909b2a413abfad23c9ac0e1187d55890e01e0e640da2cc5aaee4590cba0009b1ce3a049e2badaa24102100e05bf1511ae2f6374d3f30023e6a0786d74d43523f851aec23a804b6ec9430e70ffaa4f9403c4cd162e112aab43be9570a12c15fd557f5bd828281926023a09cd31e0020120026b026c020120026d026e009b1ce3a049e29a113b265beeb63440791138552f12af1919d8439b0d13dd3a937e306c88a8e5c04b6ec9430e70ff89560074888088655edfa55324239a775de74b5e99e20b05ded62708e358178820009b1ce3a049e2853eb3598c031237ee18c9a9f5494fc1aa84086d30e5ad8a9ef3534f09d0f9c1c04b6ec9430e70ff8dea96a7b8ea2063ee0989cf652950d5f32e492e1ed6017f8bdb88783f06124360009b1ce3a049e28be0a8d55b7cad4c5bc28725a6866f0274c4ab0f34fd870ce176dfc48b6c076e804b6ec9430e70ff8b7f9a4eed3845db2945aea88cffd4d96263db2628d1c54229b26fbf565ee75320009b1ce3a049e2b455f7264b4559f95da8430e6e7ecee57794aeec3e812c36b584f955af00066a804b6ec9430e70ffb629693c72a6600b4e8a0298617f313755c7905ada6900611bc9b934eacccef4a002012002710272020120027702780201200273027402012002750276009b1ce3a049e295eb04bd2b8c5f0de2d75c1ac64b63e3b847e2c5df8a7ef7bc16cab080d0979dc04b6ec9430e70ffa9ba8a40bb573c891a60368abeea41f043b11435a9b8c689255a9a7e3c38878b20009b1ce3a049e2bc1f20003fb4e3d596961d9e4e6d2acc740d9c5d71634b80e064c9a2b3a4453e804b6ec9430e70ff9e5264d082c6dcb1bdcec9b15dffabd8e4dacaaafd15228b06df4b240a30f9a060009b1ce3a049e284cfbceac911dc98d84da1fb95fe45d925e57f21bab0fd3c35a15f3e97a1fa5b404b6ec9430e70ff85473740332a70e928b5f93fb4e76b2fce81ce2bc5ea24b3fca15376968449c620009b1ce3a049e2aa00f1422df78c74de42b3ca59b26b3150ef9172e32d2ad48df9cf4ac91b4ec9004b6ec9430e70ffa60d6efe58def44a942c7d7e437ad38314ea56eb38c2071edc0dfe84fab122a4a00201200279027a020120027b027c009b1ce3a049e2956ea0e7590a470b89cb4defb561f7af2194f6ec7d8d09d1eecd11da054cf7efc04707edf9a8e62e6632154ae74d72cbf208021b88ec8d3d89a3fcc246e6532354b918b784c81030a0009b1ce3a049e29f661bed2280d0ed7013a6a83c815eeaf2f371937ef8775cbca9c6547fb88d3dc0164b2667771d78dd9f4f2edc481f7da2d6145331a3bb4151fbabe7c6b813512b2234aec5f4f84660009b1ce3a049e298c020aef6953d33866a09cc89dee09f578a890c4385f87df8cb944568c4d9b640077a2e45a51f57c74d6367ce14cbc71ca90f74325ead8f94b0d78c0e2b4e7976cdac6123f2e77da0009b1ce3a049e294e15691cd6312a3f20d2eb6556397de2a7a3b8580dc580adf3b78c680e994d300052db4ea420fc3916cca04d7dc68c7d4b33deb5d237d7fd3e68f2fd49c226d7e5845c0784aafdc20020120027f0280009b4738e81278a34a38322d1c17d35307b19a4f80817b9155b7396abc89fd2209abe3be7f061da000f27a029c61715a106d9907263c794e9ad53a68b799f87058eff8d6e80333dba70d732998c88b88009b1ce3a049e290ff9a51008ae230b3184d36653d4c6d27fb65808a589c882b8538fc4bca4792c0052db498b3a4dde7db40f336fa9b9b7ae76d2a28b9812759ca39292db67f6e816bdcb1f7380f77e0009b1ce3a049e2b2fcee3a05c4b2f94142ac213f7f244c76198027a5aca42bad5f536f6e403ff2c003dbfca726569ccb524493cdc08f0ba0b9606455926f993c9858533b8f075fa19d8a642b239392e0010120028301012002a9010b00b5bd3eb0400284020120028502860203c1f8028702880203e1f802a702a81201db0dc12eba51aeddc78aa8ca6fe7f48c0a78e804f2fa60ef1d85dcd8db83157100092002ab02ac0201200289028a020120028b028c1201409dba5e0ee755ae8682cff30e876828c8e0d71aae4f09c2df552b247d5ae63d00062003670368120146b880fde0bbdbb7b318c0588f08d44551c3e54ec67a61cbee7a289754c366dd000620033f0340020120028d028e020120028f02900201200299029a0041bede7691f9c5bbaa89936a4c6f47edf9533887cd898b43c48e401f84fa1b8b5c54020120029102920041be94e11bd39f607a7bef279a512ffde668473d582abdeac83b9d1138dcacc160280201200293029402012002950296020120029702980041be0ba43787076aa945b9ac09bff4c66b1854dc75360798aef1c64f54c3ac7903a00041be2bb535c40284a9a044668aa3a72027bd2c7c67d8df3d378047f6a74796b1be600041be2d1296ca25aba57af3985d03ea9668223201c353a0ba5fb291c69172ccf7f4600041be36f32e3d19d68b9dca1c96fd0849d0e531463f7310cf18d58508f4fcb781aea002016a029b029c020120029d029e0041be09993ca9ab248754c5493075aca5bdf1aecd8baddcb8789f8ced0c696d2e1c200041be039bf0efb82191145aab6744643c269324301a1ca59ca4fdda3777ff4c627560020120029f02a00041bea41e675dd03f496ccf134ab77f347c25ae695f78bf00bf6dfbaa9ab960d7f7c802012002a102a202012002a302a40041be06da987a012fe60fff9c22fe1a2189b5cf98c08025bf4d30c4afbdb281738fe00041be105991d516c9cd73760f45869f504ac583f8b4b25c284a2c93a2305deb54daa002012002a502a60041be1b18ba88d973dd28627336590f9ce9c1dd8930d1043d9483190995b9196be9a00041bdc0155baa01acc753e8839764983c949785487b564c1360440d8eb330da1062c00041bdd1e286edaa65df6f51f637174496a783b960f877e63bde8ccd27b744e2319f401201553488f139dea28917c210039ba134cafcbdc2c4f57ebea208bb399ea2b53271000820039f03a01201fc0cc3ae9eea50f773258af35f2b83e4852883a89330a449f703f612b767eb7900062003c703c80103c0c002aa0055a01128d1e058f1cae1005c732f390a2df871be0fd4ed4906afc0a6de574f67dc6f76000000000000007d1002012002ad02ae02012002cb02cc02012002af02b012010678c33bae80e452f57ca3cb6276bc3d505a2836bccd5841e5705b0d2ae0e27c00062002cd02ce02012002b102b202012002bf02c002012002b302b402012002b702b802016202b502b60041beb69ffdea3d8261cb8844691f963979baffcf8a57e0dcac0263cc7076bd4976a80003def00041bdf68e4692e23ba70779fe0e0bb7e6af1e1df59795a83539dd6c981d75324189c002014802b902ba02012002bb02bc0041be020a8c9757834a47ad121f0e060b436d1d214ea611b0dad45c6d517cbd07aae00041be09ebf611c47fa98de5318677b48a231d1e6cfb05b249fc0d83b5d980fdb7c1a002012002bd02be0041be7d919f39df9c1c6c74d5c77cfb1400c148df23f56b00db1f54fc358d914985300041be32da53dd1d950f9baf7967e6e1d19d5d72d6b8c575fb7e5e9d95cd925ce962200041be17d6e44a1997f23c8c046885eb47464ea9a75cb79ab5d1dbcac56231c7b490a002016a02c102c202012002c302c40041be3313e35e7fcd0ef5d2d9cbdd477cf88e6fa10443c62ac962b2214f8a79a60b200041be03dc59e2f48ea3f17792225fb000604486a85a99ee8eb4063419270a4f40fd6002012002c502c60041be87c0347ecf1b679e4dd5f956bd9951e6f109fc09cb3042138a2b8945515378c802012002c702c802012002c902ca0041be1bb43099106440397681e96c15a85cd84ddd73660ca9d79048bb2f67d36f64e00041be299ff7b29d595fec88b677a8cffe9d5444fadd17d1774bb0e2b9d4327a5923e00041be090ae0943403702ddbea54da22bdad54f451e11971540c3160d705fba064bda00041be2630bf77c6f513fa204326b39f8624464acdef39ccc4cbd0c901bb826fb694e01201d35559ac793ff0bccb29cfab946bc0fdf38a728333ce850c778798bcfb7a6e8400062002ef02f0120111f0b59d9872e78b3dfc5657eece386d06bc0253570c4258d561ab5707242e71000720030f031002012002cf02d002012002e302e402012002d102d202015802dd02de02012002d302d40041be8bd5413b4f996618eb848b23e0ca4baa016d043426b18ec8b87ddcd9ab60f41802027002d502d602012002d702d8003fbd42894affb9cc86edcc3bd6f32b7d4fec3a921684242f27983f7456cf97f72b003fbd56a2395de25c5fb6056d11eee1b0aa69d73fbcb472310789b413eafe0cb2c102012002d902da02057fad6002db02dc0041bde98522edddeb853c151b0bffa687227fa74d43a0dc677255cefa9d84596d43400041bdf34fb0b5765590951d5099facb7da1a2e528fde06baafe02d05da92e166a15c0003fbbc9fac8af86a5b514746f5d8dae031c72c6184bb96576faad41c5385312ee40003fbbf7754894860699182fa67541b2244cda826d0830d7b77764359424414cae400041be728e8b26642fde1e3a3925772ac4f6816cafe8c2cf28eadf21716df3a76c5d5002012002df02e00041be29017e9330006726e91ffd73d736287f4f56600018e8c6d01c38f700ef5d086002012002e102e20041bdc496458546da8d5d458113eed17f0b4876370c8051988e300bab8ba4d1b996400041bdfff945cdce8ce7ec46f53ec08bb3c35a0f65611bef6a04196f2c91bbe8a9134002012002e502e602012002ed02ee02012002e702e802016202eb02ec0041be65e940bafd99b04531e55b0b61cec25c631fbc563daf9a89bdfe7bbad7b1669002012002e902ea0041be09eb80dfed57dbf3f8e69469ec641c8601d0ac11603f15f597c95114e5de82a00041be1bf443f54401f1f18e7611251c5beb1b467adaa83b53a08ecb730bfdce938d600041bdeb8116a953904b42561d47319c0cfa4935acefe06c44e9a87090a8fb19aa7b400041bdef47da1100b5dcc0b40f45bef417f80fed20155aac8c80221ab0eab0f9be3bc00041be96efc56779faadaf25456a47d0256c421f745cac2d1d0f5c68159417fcc798580041be8fd6e07318cac5199f32b2440ba05b1d3090f96357a82dc7fb3e7dd60670d00802012002f102f202012002f702f802014802f302f40041beca92b7995da4995d23c6c5b830b8975dce9589972dcc14d63000b93241c21d0c0041be72d6d014d9a1ccb40fa878f1e84fb60a80d17a8dc6ba81f3a6d34e4b3dbafb9002012002f502f60041be363370e5d621fca41ea483b779bdd8769ccff5d1a160f9178cb2d0043f134a200041be01284e5618a2259e88b738ecf0eef90a2885f9e5e5a33ef831256c1e93c0322002012002f902fa02012002ff030002037ae002fb02fc02015802fd02fe003fbd5b8321bb7dd70d99d85a4b48eb320143e8da8bde8b6f12c5a1ca0d251d473d003fbd6a9b80f87af2f8d31d6a262e8018b87aa0e06dc45af96e073c5ebf2369e5910041be1f32bbca65210e1e4f2fffe92c7ab069889dab7b329bb848582df646aa25fa600041be350cebd2a31da39e3378d1916d512421489302c845a105175111145296d89b20020120030103020201200307030802015803030304020120030503060041bddc1c9f9baed052b113a74a2a16349a85c59fb9848197eed6b92ae865781167c00041bdffe5400e5326b1839afe84a9a70d9798fa92d4f36d03841aaa65e39c5c7a43400041be36f7bd19d449867fedd1f8187bb775a644c1c5ad807e25dc59e458a84d4adf200041be23ad71e8c43ca1d5960605d0684202da49cc56ea9651d61121242f01a85fb9200201200309030a020158030d030e0041be09d12b3127c562610af49f578a62435f2b33423b5510bb4721742dec0bd08ca0020148030b030c0040bd8af141e1b03b3c03f45579d3b3bf384ceff80a858b6f542a45dcabd28acb020040bdbe73f319b6cadfc7941d46f530764276b8ad58331b123f9f8cf7518af76bb80041bddfd0f40edff9d4e72a6e5c3e7f49a65ba23d918598dde73e3ba3b54cf008c3c00041bdf188a965f1822ee60a5b56ad87f8a506b669164f16f300f0b055d619a96ae0c002012003110312020120032f0330020120031303140201200321032202012003150316020158031f0320020148031703180201200319031a0041bdf7763daa94751239fd8392256b57085cab2dd2904f586c17e7cd4d3bbcafaec00041bddc6243c62dfcb6fd073b6435ef5dc97b94c9339c28946517d06d788d8b2bdf40020120031b031c0041be3c40b17640b53428330255dbb9ebccd0b216e9b5694d5f6f281e14c16e617f60020148031d031e0041bddae8a1d0a721ac946f9557605876dea246004e0e79dee2aaa53f2f488500fa40003fbd425529534ac59d74665a2dd99c8b05b48226dc90d276d54f106a8679f06dff003fbd61a5fb51ab1804848f719a022cef30e5c397af72669714d9852d0877c68cb50041be1dfe847cf13adf00670aacc9f8e13df00676e1dd3595416afcad5ab46d84e7600041be1a58e9f037f9aa703105dda4432ef2cf2e1577feeb6e66b5f72232dd1d8782e002012003230324020120032703280041be5dd02bcfbecc82671b936d47b93b63ed4ee742c2d81cdcebb80ccb97d968b310020148032503260041bdc1ae511da3e1f0d2e6592710a009dc56b3f9e3b3a6d31eea6b63b1eda8d974400041bdc4ac7342f6d12a34d01c90676a28d1a5167f8065adeb8772962447f0b902fec00201200329032a020120032d032e020120032b032c0041be12b34494e0f090f07e2af10aa82b42cfc092e4709cb02f3f5682465797f4fae00041bdc5096fc2cb6d23b6f012d23e24f5e42f460f6d7296908059c7739701ec576fc00041bdce67327f61d9ce857aace89ef03be12c1a4f16574e02c45ce28e2053a48bd0400041be3643510ef20228340d6aa065a71d4b9d29f9aa94a1034d013e0f137eff8b1da00041be3ed33b0df63f8bc6cd44bdb186d1f3306de7aa6d69714f3ca35782c4fb4b8960020120033103320201480339033a02012003330334020120033503360041be4efba3ba63b7566f81ce9cc04ae1f67b40da3dc2813304878a779f8ad3cc65900041be5c252e8af5f1d679fcedc0a265f123987160ce282755ebaf1d090a12d5c47a50020158033703380041be7f6100cfa0e374d347cbcebd97e7857de43c10a03e9dd3d3e605f808ba4451f00041bdf4a9990a0c33cac2f3211d9335a25d6f25f894a76e38c9429a10a9e0bf6024400041bdcdb679a65b8cb398076201883bb0d8e80fcb0289622f82f929b98a535dcca240020166033b033c02016e033d033e0040bd873be25710f5ef480865fb163c614a7db381e8b08fe58847ec8edf5b3ef0770040bda7b2f646eede090f0d8604ada07c6f7b0552b0a08386ac9370be3bc509d6690040bdb000be851906824db0dd13019427cd930e954c2e836be191995b17287e08590040bd96ace07a1217a0c463e7cbc059a1e73408ba517114e427bde36749a9fe076b0201200341034202012003570358020120034303440201200353035402012003450346020120034b034c02016a034703480201200349034a0040bdb3202279e99fdef177ba6634942690c4b870bdb4c5b8bf1e4313d8ae9799f00040bdb97aadec88b02287d9fab623cfa8127912e31632dd1507ffb91ad79d96ae2b0041be0224780072cfb043381fffd20f29d927c3f7a3d19f90fa7dc1b5210a8b4848a00041be0aa8be70ffa303f99ec0381badbbeb91f99253b20354d5fbb8eb8867f60ad8e0020158034d034e020120034f03500041bddd006f0db5adff898893ca6806c55d027ca42537a52589d1de3606efb4c4fdc00041bdeec09f6705812851a19c77c40ee150346dc1b70b69ed31e1d3d0425007f28dc00041be1c3786f5936f933ab7c030e91add1c6f97071c54348ad1c3dece51d981f2f1e002016203510352003fbd7b0aa37add8955a0b31daf0d5df9d6dd9b4b1331004a993d7a2732ced0abbf003fbd70f368534c8c5d419ea3288ee96c2077d3d838f596d09356fa1ef30bbe18a7020120035503560041beba7da857b09b99185819ceed2e20978ff2f8d3ee19973be59849d93f1cae42b80041be449668a44947215f4953fb4012561c05d0e067501f17e130f89b8fefd837e5d00041be5051ee671440ef087cdf839240d81c5d6b79225986fd3cc3a93e24803a2138b00201200359035a02012003630364020158035b035c020120036103620041be15f49b86a9316fc6103c6d9ddfb3d2e83be6fa0777e3a26d241b036fad50f8a0020120035d035e020158035f03600041bdd62a290f6fd6bf276b6257ac8e84d516e418af8a657780cf84237540c6cb7a40003fbd47921f864bfbb57c79004417fd259bfa2e209fb042ce504f3069b121d25cb7003fbd6de184fe8d81cba71e46bf71c5a0eccbe6b860d1492e77c1b769d17c0189510041be65fd274ebc1a3cf4cf94b8de80db06928cfb515e70cfba1841eb7df9236645f00041be66d2dab25c5629e27b6e7032d3c09575831c2887a26824bd58d2b7f07cb421500041bea4821d56a4fa321cf4036eb5301f1e964d33761d1a4cbbc9a0f3b13ae0d1684802037d7803650366003fbd001820171ed69024daa2493d2b353b3c994652a391fabccee0bc0fb7abbfa2003fbd160cc594e654adf46da27090ce30d2173ad1bf897ff784c5b3da22f9143a920201200369036a02012003850386020120036b036c0201200379037a020120036d036e020120037303740041bea83dde5515c66942124b3990bf234c572a83c94495f022f1d49e7bc8f68c50c8020120036f0370020273037103720041be60a844223aa04a13afbef5f24247a2d156d342704f4c1649d716517495e5d030003fbd60e0c0fc874550ef665da26208c9de759e3d15b6c23a14580c6b6e0cc1e5af003fbd6f8b9b9af11f576aced924ec671f0f6ef6aff9cb23a62a269ce185e1a7365d0041beb3503b1117458e8908ba71424a078ec648be57c1706c6685da71731c3b85dd38020120037503760041be56866607516a4a51852cf9b9afd2c12c05faec5e811502c39706a1340ae3cf5002027203770378003fbd42226d63731ecd32fb281d31bc58a478a1f810bfd74972f46fb3f51685425f003fbd68a75bc6b648dc60c8c8be7b430bd34062051cb891987f250ac01cc659dd8d020120037b037c02012003810382020158037d037e02057fab60037f03800041be0c506c2ddb9210777ff21e3234dc5ef51bc2a9d8631a304bf64e25a84ca6ece00041be37e060d689c898a3adae11ba12f2c8f78652945c059870cdd4adcd0d8c2320e0003fbc5ecb300bde17906283b28511dc1ef75b15d15f62ddad64a893beeec17fdcf0003fbc5ff16d3f9a15b7a9c452b381943d1db17dbb2d4a115b299b6ff6d2496195d00041be8e4683041eb92670047ef67b439008f41eaea02c6513d1c7a0954f139bd8dfb8020120038303840041be40fd331aaa768ac76041bdcc5a7d3a7053165845770a5d30198fcd0e6a9452700041be6f22189aa61c385bc77e041a3a21d981e15389a90bf1d59269f3ecd0500342f002012003870388020120039503960201200389038a020120038d038e02037aa0038b038c0041beac2f68ad9dfd26da3dda4e33ad1e7df3d678ab24b200d5c053c4cb1b9fb4cdf8003fbd5b8264a14d7c840136f0d2c102126b7036dbb3288f92dc31c400f08f461bd3003fbd602ef8a7666e108733e40e2c13af5aecc4c5b8046fae6427cd40e073b328dd020120038f0390020378e0039303940041be59cebf470d43b5e0149130a3d6e8821095507cdf67ebab42d261e9eb115b9c5002016a039103920040bd8635b137f6667b96ae4459f9a8a359b687faae59307920867fd8b3eb42661a0040bda62dfa2a319c3bee59fba009f40a76be064a7fb27370c47811d8c4e5feea95003fbd5e249e73202fa676cd2b7676f0701f2e15ef6d7379f4f98af80eccd950dd03003fbd5704a444eae806e57e6547b4df7507b18d1321a0955736e38ee8a0f7224d9302014803970398020120039d039e0201200399039a0041be49efd6725a09be9eaad7b3ac74238c243e2290047dbc0bb45635f3d3a807eef00041be06bb8bc5bf57b7c27f268a7fe2cbb38f2577a03984c54396d9159e5ae593e220020158039b039c0040bd921990bcf0ed81c36cb7be49c97adee85d5df4703946b4247c09bee8461b790040bd9af90b511a49638c5ea18e2304d23ecb9e73232640e1ea66016a1bf74a0b9f0041beab767570e36711750eaba7285fbc7445a2bc9765898ff41588825e7b61baa9c80041bea9e1ae29e3bf40782d382bd1d4474c7c07d4c3ac80684a05725977bbc448c65802012003a103a202012003b303b402012003a303a402012003a903aa02014803a503a60041bf26f5850a4eb8b9b753ee4f5f003940003656da851e13417ffe1340c79be6436e02012003a703a80041bea2bb40f112ffaac45f54209c9a187dc95f9a6c4b07b264664832323398e229980041be76ae77adb8998bc707adc115e543c4b093332b2079fd7f5b7edefc72a67f22900041be5451ad64144940a8ef9f9d4ed8fa7cfd54553995e4312e8efd5320073764b65002015803ab03ac02012003ad03ae0041be8e8033db1467cacea8b158f0f61e682de06e8a5947504c904f1f703d2be4d9e80041be83062b2a70d34e8079162a8a62e3998d947e9f921e4f02d19241360541973c3802016a03af03b002015803b103b20041be05349e4d24ee3ed10c2554059c914657764f8f7d80dec43675fa3bbd4b1845e00041be3c50a5f378e79bcfa49fd3faddabb6528213d5fa2af88715157cd368023dee600041be78c3f5d979d69f4c1397a5e66e00a59e3605336258d9401962151a9272897f700041be562ca3df55eca4435368797093fb9d5a5916ceb184ca9b27770104b3119dfd1002012003b503b602012003bb03bc02015803b703b802012003b903ba0041bebca71c72a007163afa5f96fdd58df82b464f6fe38b9acddc4cce23ea7dcd61180041bea2b4087aa806275c114247c789da5774ed82652fd681211a9b770c52c69e77280041bec6775d5ce894348e832442b8a98d42c686bc1e5ea24245973165304cf4e81fac0041bef61b529ee2ae97d3798223cef3faa54c3bf81dfb1bd7bfa492c1d5a97db9ef8c02012003bd03be0041bf01f3e7bfc4e7279fe0f7c8bf121a411ffd25c0c77a51487fcb7f75030bacf11a02012003bf03c00041beda9f7e00138320e0f7aa6405ba17a8ff25b80597c7a03c11431980b974882bbc0041be931defc8334a256c2b4cf3d001ed1236bcc7552807f34364c8e7fa5f3a3502b802015803c103c202012003c303c40041be338fa441738990ea9de783b98627bb69ecc6f311185eee86e433d034c27082200041bdc765599106d178fbb8680b7da8334f81b8ce6b52fc90c474f401cce034afdf4002012003c503c60040bd80f4d15366a1c672ad2f0b3eea20770260630f70582ed008a6a27275a8b3b20040bd944782557077d989b3883aa7499be3933cde99d73d1bca42aed3d529fb173f02012003c903ca02012003d703d802012003cb03cc02012003d503d602015803cd03ce02012003d303d40041bea49896dd0a389eaf292a3573cdfb37ff4b89c4c9965d8c83b1db8b1edbb2f20802012003cf03d00041be54ecd4ce0ab39faca325d3ddda538fd8b42a89917b3b6fcb6dc98bccc7fe85f002027203d103d2003fbd6e6b860183400ac934336143bbceba71852086a2e294d2b9da82df941a0a5d003fbd4f9c8e40e7adbf8da237ce109a709b69bd8659879abdc7396c329782c421c10041bef1ae99941c2cc71df69a0db88aeba2c344a78a6e5862e10a13551b612763b36c0041beee9dfdb38613f8a22a22aae40182bdc7ad037233c38e62858d7debe7b2fc16dc0041bf20f54933a7c63fd382f8f73331476228f35fc2452bb787ac960cd75c4634a8220041bf05c117e7e0b6d8313ce92ec481b84237bc068b8ad0037e5a5dc69f8ce49556b602012003d903da02012003e503e60041bf397cff92d1931c295bf1aaf32eddd71239494f0f4b118c631af48935f7fbf65a02012003db03dc02014803dd03de02012003df03e00041be5b36a4274fc1807470e78b17fd3734c1e5562f9a7bda62cea6e772b06f1333b00041be51ac966416140a61571140186209bdfba4fe80699e0773cb4b09f16c6658d49002037eba03e103e202016e03e303e4003fbce0771c6f4d07aa118cde54506486774263ae5a5443050f7eb9744abb52fe84003fbce2dcda8f91e3ea1f380433790894d3a17a30dd674c65962747aeac7f3af7340041bdfa4369c34507d9c7f5ec189fb3d3362d9384ba3973d97140123a6e36d32d45400041bddf5bba420d0a92a63445de03ebdeecc9e1a7c592b7e30f2450c25188c32d9d4002012003e703e80041bf30f494b4acbf53e2590d235436a379715b27f4e449a92f772fa0d133d1dbb28602015803e903ea02015803eb03ec0041be77b5a54244cc2b575b24cbf104e3904e2684d327477abe42d921bea3e24f86d00041be52ae3cf73eb1dbfd7df452fca8fe6d240a64513b7d3fe36eda20ff97586020900041be65974173117b5425894beb62efca3b276a98f9a5f22a2a429763f409f5de52100041be6075922fcd6ec7f0a0f3e32d6828c8ae03395763e4c5ecf19503052f1829f45002012003ef03f00103a0c003fb0101fc03f102012003f203f301c1b9e998aa2946eda7f031d9083857087bc975c908ef1c34901bdb6f49e975dee38e575769805544cc49b2bc01134fc82786a67522a1e7f11cd3e9d9849af9f37b8000000000000000000000006d8affd79644796c4edc9b2d28b06adc64a247534003f60101d403f40101f403f501c1c69899ed4c3a24c5f84b185d6346f3060bc25abf657991ea0d8f8125da3ce11e375679d7b9aa905754ecdaabd4afa6a069c334c9d3aec7934d6b599c53e7043b8000000000000000000000006d8affd79644796c4edc9b2d28b06adc64a247534003f602c501a524100b8d7492c122a279d2b3ae24878b1c105312750714c4d3952be405f0654d2c7f02b0652410a198cc2c5a2ddf5387a4f96243be317b02114f51c357e24680000000000000000000000000277ec7825b7da67d7867d5608fda44dcbedf5db04003f603fd02012003f703f802012003f903fa0083bfcfe23047dc7946a3d27c0ce0b89a85c5a9ca79485942016c98ac23e06b802b658000000000000000000000007b1b7a075f0bfd9509a1f2f7774e89d5484445a8c00082bfa33f3ae14d89682a04c2b0680414dc7b39d1feb09f7c7ad267c2b2154ac1711f000000000000000000000000eb05e1b6ac0d574ef2cf29fdf01cc0ba3d8f9bf10082bf9fc2c9192c4b860df613440b6fb7d93e984764688b249143ac1303f0d70cd793000000000000000000000000e54cd631c97be0767172ad16904688962d09d2fe02c501b525eb5b3c5f6e6dcd606bee7ba07a0ec83035212849b7e0559499c0f6bad54d211f1574bf623d14787708c5fdd565e329a25abfa49095e984426f19bcf04974800000000000000000000000005991b495b6a6dcb578fa97224cd15e86f6cd79e2c003fc03fd02012003fe03ff003043b9aca0043b9aca0037a12003e4e1c0405f5e1003989680020120040004010083bfd3eeabb33dd4e93dc0a086def14e9a22fa0f52c3b82d9180d2c9a3a1d2a1dcd000000000000000000000000036af1b0fbf0af5d39f20c827a7d953e9650228b14002012004020403020120040a040b020120040404050081bf5c1a776cb04e12edb7153481cc16b92252b8b35a74f9bc8f727ce60811ce3906000000000000000000000001d712eb2cdb5e190ce438297176fbf713f97733950081bf09b8308543189f6c87537e3775c7b32a4be67b773214907b487558dc55e153d80000000000000000000000022c1a974dd897d07ba767d50d20ad958b195fa9be02012004060407020120040804090081bee3c6f6e26f4c9bdc32af4010dc1cbfe1760ecd8c2baa8d4434f6df21826855a000000000000000000000000441a93191a834877917cd2c0735a09e3a3e00fd940081beb04f1c7228c06e691a04955fc9f82a639a5fe1048ef9ce48146542f56c2563f0000000000000000000000007a0d3c42f795ba2db707d421add31deda9f1fec180081beac7060ec8093e1f460605cef481914973aa2a52f707cb053ec893417d2361f80000000000000000000000003154e640c56d023a98890426a24d1a772f5a38b28020120040c040d0081bf69cc6186bf9dce786da691950a0fa416a8cbeb9ace75d1e7d66c32463d6b6204000000000000000000000000917e94f07d9f6ff355956d1a5160dfb5fe6f58870081bf0f5f8539bf36a511053e05bb025ccd959edfd179ef9866a45b6df0a567882c080000000000000000000000010e4c6e30a78d2a3059a550233558c9fd4473c21a0081bf11b83deb143c8d529b97b41027593ca429502e63b50a2ebc9ee35f6cb766f6e4000000000000000000000002552b992ec09a2c1bffbeedbd15219e97cb2cc5dec87bf018");
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        token_factory_addr,
        validator_addr,
        ..
    } = new_mock_app_with_boc(key_block.unwrap());

    app.app.set_block(BlockInfo {
        height: 1,
        time: Timestamp::from_seconds(0),
        chain_id: "Oraichain".to_string(),
    });

    // update config to mutate bridge adapter address
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: bridge_addr.to_string(),
        msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
            validator_contract_addr: Some(validator_addr.clone()),
            bridge_adapter: Some("EQAFzUWT10H8NZtXn5sFrv_MmrfMe3iJJJV_JDHUPR0PdVHh".to_string()),
            relayer_fee_token: None,
            token_fee_receiver: None,
            relayer_fee_receiver: None,
            relayer_fee: None,
            swap_router_contract: None,
            token_fee: None,
        })
        .unwrap(),
        funds: vec![],
    });
    app.app.execute(owner.clone(), msg).unwrap();

    // create denom
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: token_factory_addr.to_string(),
        msg: to_json_binary(&tokenfactory::msg::ExecuteMsg::CreateDenom {
            subdenom: "usdt".to_string(),
            metadata: None,
        })
        .unwrap(),
        funds: vec![],
    });
    let _: cosmwasm_testing_util::AppResponse = app.app.execute(owner.clone(), msg).unwrap();

    let denom = format!("factory/{}/usdt", token_factory_addr.to_string()).to_string();

    // update mapping
    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: bridge_addr.to_string(),
        msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
            UpdatePairMsg {
                denom: "EQAX_18eFGby3HZaB0vr95rg5Te3kHoaUOLG3iS_QjtMJNg9".to_string(), // usdt contract
                local_asset_info: AssetInfo::NativeToken {
                    denom: denom.to_string(),
                },
                remote_decimals: 6,
                local_asset_info_decimals: 6,
                opcode,
                token_origin: 529034805,
            },
        ))
        .unwrap(),
        funds: vec![],
    });
    app.app.execute(owner.clone(), msg).unwrap();

    // verify masterchain block
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: validator_addr.to_string(),
        msg: to_json_binary(
            &tonbridge_validator::msg::ExecuteMsg::VerifyMasterchainBlockByValidatorSignatures {
                block_header_proof: HexBinary::from_hex("b5ee9c72010209010001fa0009460311f786de79ad426e88ce5f09df1e4e99ae7deaddef91be439fad5628c64b7d41001701241011ef55aafffffffd0203040501a09bc7a987000000000401014787090000000000ffffffff000000000000000066a50b4f000015f140f37a40000015f140f37a44b22b62500004796a0147870101478393c40000000800000000000001ee06284801014d3b19a7efc9dc2a71d96307bc08b20f4dabb9dd43b37863e1e849acf1f0948f00032a8a0434b3c217adbf3c28839881ee29e8e1335c3089d4af38c2d0c6239e57823a5f9dc3bfef09eca57faedfa609f72f2c3ca3918b77cb3d9199dc6f8ada70f3fb2be301c401c407082848010106c3857dcc52b71a133ae1de54839cd80f5d8eed1b0a22900199ce93fcb3523500070098000015f140e43804014787089debda07d8e08b189db712da65dcebf1060e692640d1d31fb1baf58c97638b94ed41abdf6a5b99c2d13a24ac154abbbccf1b83b275fd49aba23985f8185d832a688c010334b3c217adbf3c28839881ee29e8e1335c3089d4af38c2d0c6239e57823a5f9d334ed8582e02d75399590dc56645514fa9e8708712e2d18b5b6680dec62cf57a01c40015688c0103c3bfef09eca57faedfa609f72f2c3ca3918b77cb3d9199dc6f8ada70f3fb2be3b9516689f858f128ed3c45bd0533482e0405cf66857f1e6815a6a51d2757aa3001c40015").unwrap(),
                file_hash: HexBinary::from_hex("7c2da4cb70359056791792848c514067f3ed963b3d8f700d1551dcb65dd6e73a").unwrap(),
                vdata: vec![
                    VdataHex {
                        node_id: HexBinary::from_hex("a83ac8ba66b001b55d934edeafcf864fb669aed501b652b85d8c20958fc46fd1").unwrap(),
                        r: HexBinary::from_hex("fdb0ab334ec63fc5f1eeb532965e2b7d2b1307ab172eecf7a6d189c816bffbd0").unwrap(),
                        s: HexBinary::from_hex("7de224aca20127d792f9a2b20cbc37bda18a0deb289b2b7862a0dc42661fd009").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("58b2ef25b257f27bd272844cfddac7a37b86b7c4d5d54a7d728fedc7b33a47fb").unwrap(),
                        r: HexBinary::from_hex("e6086319423571f78eee2ff903385fa81336d0de25caaa24b99db79b441807ce").unwrap(),
                        s: HexBinary::from_hex("b534022a4776e41efba38d0a2fa253385dc0d3af08fa9cb165ce1bbd54c86b09").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("85a918848b9ee8745295ae99eb0bc3f698c47d2b38d3a1a9a05234f2353651c3").unwrap(),
                        r: HexBinary::from_hex("f9b136d482ec6a3bfe90f535411ebefe66b1ce2432b5da5b0d8d1d1d9ebfa528").unwrap(),
                        s: HexBinary::from_hex("a82ff6cc7bcf80348f2e45e661726a58105bf35acf4edd14ff56462f6e849a0e").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("232117f8a4f3b2998b410415d658c7b0af9e2c56fe40f429175d0dbea39889a0").unwrap(),
                        r: HexBinary::from_hex("6692c8294d006ed03d55a097e2b6223478a49348765c8a5aebfb8e882945aa6a").unwrap(),
                        s: HexBinary::from_hex("af04c6c329c5ca5ba9e514f3eaa85b3e1d2746e1ddb2ffa30287a46502f24f0a").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("bdd50f9a683de1a59a980a87bd04b67710f9b84d34bb59ccd75dd121b234924a").unwrap(),
                        r: HexBinary::from_hex("12602cbcb3e04c30d08f5d4af69cb5bdc1d1dac91f61adb992766c84ddfe8364").unwrap(),
                        s: HexBinary::from_hex("a272ffafa547fb91736e06f14dfc14132985c4591734b09c94ff0534eda44901").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("ac594221852e2c75b4c4a25583561a517dd117a299a0ed03d72ffbd5a551c3aa").unwrap(),
                        r: HexBinary::from_hex("b2b18c6d18e20b7b4ba21e5958db0eff5f0216a1601e9ec4247617287cf125da").unwrap(),
                        s: HexBinary::from_hex("9ac6e03c01deb49903afc6009cd61527e35ffd48a1079a598f71493ed3a4e604").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("4e4770ef85c05d0b55e4c4b16078d170a06dd28b828e5020d34791c21a6dd97e").unwrap(),
                        r: HexBinary::from_hex("793fd40c84be6adc95faf9726f39e56f45497faa0b3d51dbc4b6f7daff3d73b1").unwrap(),
                        s: HexBinary::from_hex("3ce43f9a9f1f8d9acc4adb9480b89c342af5419acc4a0a751b334cf9b8745c07").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("365ff3796073a72a135af76fbf1cb94e2602728d410b968995879cc0eb8b8046").unwrap(),
                        r: HexBinary::from_hex("337cdd661ea53918f4f7106018d577135f7f4612aec4775807849cd61c72b54b").unwrap(),
                        s: HexBinary::from_hex("7d2bcb8cb0c8f4f6497e3a432ee30926c991963b300126a49e10c10b629c6600").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("cba6b6b28bdeb82da6af02b4b9735d71fb06e1b390b3365d683d909767747894").unwrap(),
                        r: HexBinary::from_hex("fe075ff0a67e9a58e1716831a1e52bfb6cbd1938085e9052ab04568709c469af").unwrap(),
                        s: HexBinary::from_hex("ab95ad98403f395714b94bdc00526f775b2dce2efc692204dee53ed2890a4505").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("860d957a75b57c555a6f3b85a0115c8b6b703e20b353274871aebce2b6cb4459").unwrap(),
                        r: HexBinary::from_hex("d5d52c74cef702b2c83e0cb31cec457288be641bf9eea6504ac4855fffe9458d").unwrap(),
                        s: HexBinary::from_hex("ce64b95be7242f52b27612fb4f2cbee70e11e9dd3426d51a59dd8cc7dde2120f").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("edb2848e3487faeb02e70a10b50acb6ea8bcea699880bc7c09d46914a223b681").unwrap(),
                        r: HexBinary::from_hex("e75653f9c163de493c3374a1e15f8e2ff17e94683d22df4d4a2917384822071c").unwrap(),
                        s: HexBinary::from_hex("98c59f201ca1b80ec283198439a5ef85165548525cc82414c1c8a057119c3d09").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("5cbc78b52351e2e2f1dcc44af433c95b38112dc83a79dad9004ce6802a7ad7c4").unwrap(),
                        r: HexBinary::from_hex("16d8ffecf51a8a7b582b0f33d55bc871d892a3882699ad36530352658a1bd82c").unwrap(),
                        s: HexBinary::from_hex("b87f4d67c84c38ef816d318b263fd5a6326085f182f8fa5e73e59d6fde14280f").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("08a6298a0e3e80d34c1120a604f8f03bf568461672b91e1091ca66a5201c983d").unwrap(),
                        r: HexBinary::from_hex("fd0ce85dfb3cfd2e3ec130935a9a4c1399bef96dbdaf494657d1e5da0be93e64").unwrap(),
                        s: HexBinary::from_hex("e27ef33e557cb46902909d1558caf506ae89c26b3c4e2572a566a830829d380a").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("6793359446bab4f57cf5fd82d7921a78d8ac1020549f669c3057071b722f040d").unwrap(),
                        r: HexBinary::from_hex("858f1b80adbdf7953fa9023ef154a5c9cddf592f312dadcaf2190fdfce317c29").unwrap(),
                        s: HexBinary::from_hex("6971f6f67b5d65b5788fc7f6850054f2b1054f814a49ef0ff5669862587a1c0b").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("3f4eeec76915ea95c3fc38746ca2ff35594e0500f23b215c0e56a901078d431d").unwrap(),
                        r: HexBinary::from_hex("637aec7b24b24d2f88c7b4e330e94e0cd53e351604fcd62f2683c170d4ff7775").unwrap(),
                        s: HexBinary::from_hex("0fe417fc3eadbeeb129678b612047dfe8936ac062bcf9181314d0c19beef400f").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("aee8465142383e4dc4f9fa4309910ed60eefe03b8e82e41b3711eee6d70c8000").unwrap(),
                        r: HexBinary::from_hex("a1784e3538a941fa6ad53d9cee29228f6a27cfd38a327108925392824b78d9e7").unwrap(),
                        s: HexBinary::from_hex("3b32e0ed662f4fbf637d286e8169e25abaaa843105b5aeabc8b65053d9e5a700").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("e4269b3118bee20cfb0602adb58ec4b79fca7caf5d74f2d9185043f325872d00").unwrap(),
                        r: HexBinary::from_hex("342e3a112d156011cad066e7a0e7753a819d0c547c7bdfd9162461a8832b01c3").unwrap(),
                        s: HexBinary::from_hex("6dbb56aefafc1886b290c7b8144d41ca35a94625c25c151a96ecdd452cead208").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("0136ef5abf88e669eed0a343d08bd05f7f199a0004b00f58e89f2d35e617fd76").unwrap(),
                        r: HexBinary::from_hex("04b713dbaa5cabef9bf089578102df01a1ff9774881911941dfc7f407717c9ee").unwrap(),
                        s: HexBinary::from_hex("d17cdb6e32ff71528649ec0efbbe3692edc574d7e70ee04d9c30c795f69ce006").unwrap(),
                    },
                    VdataHex {
                        node_id: HexBinary::from_hex("570ca164bb0476fda4fe53d7f9eeb31b7250fb6fb112596cace3259872b6014e").unwrap(),
                        r: HexBinary::from_hex("2ec5cdbd0bab2206a895a72f95feb2ab30b355a50cb3286ac487ef9c955fe9a0").unwrap(),
                        s: HexBinary::from_hex("c075c9fd14fbaa4e300bbeae3680c95a8fc90d33839320532efaf025eb0fea0b").unwrap(),
                    },
                ],
            },
        )
        .unwrap(),
        funds: vec![],
    });
    app.app.execute(owner.clone(), msg).unwrap();

    // verify shard block
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: validator_addr.to_string(),
        msg: to_json_binary(&tonbridge_validator::msg::ExecuteMsg::VerifyShardBlocks {
            mc_block_root_hash: HexBinary::from_hex(
                "11f786de79ad426e88ce5f09df1e4e99ae7deaddef91be439fad5628c64b7d41",
            )
            .unwrap(),
            shard_proof_links: vec![
                HexBinary::from_hex(
                    "b5ee9c72010214010002790009460311f786de79ad426e88ce5f09df1e4e99ae7deaddef91be439fad5628c64b7d41001701241011ef55aafffffffd020304052848010111a70415d93f861d5b1dcb8aac3b36b8a5a7d1cf4ab48d269296f984e3433fb10001284801014d3b19a7efc9dc2a71d96307bc08b20f4dabb9dd43b37863e1e849acf1f0948f0003284801016c04b8e2ac4f53dafff33d4fef852aa128ba0e13ca134c1a02ddb1a4b89b9978001624894a33f6fd4a7ff3ff2b5ad717867ca3606a50baa0ae44bebbaa6b93a8d915cbc10d6bd070133ef3ab24477263613687ee57f917649795fc86eac3f4f0d6857cfa5e87e96dc006070809284801019134b8cf7d0bcb35eb2507206267e3f28cf788e6e92aca317533d140ce87ed96000400010228480101dc6723c5ad75303f405ca1a3f92f23972452d52b7e185231d81ed004b44c5f5100062317cca568d88bf7024684ee18040a0b0c2103d0400d2848010117efd5f43c1957d33a15a5b68e9bcf13ecc5f78d7b1563da0f6b18ac0513d84d0002210150132201c00e0f2201c010112848010153fd5319d537db40029cbe99cba2a0ed9a75c5b20a279870bf59dc700e565d00000201db500afc02780a3c38480000af8a0721c0000000af8a0721c009bff36e49ee3413aa4989027e4d3d3760150f47ea9d66145f0456033e8fdfed8ab908199311a96370770ff3870756d9947115d656e0122c4b25cd975d64e4ee88800023da6100000000000000000a3c383335285a621228480101ea66196bfe106add86fc565d9ce9fa521aac6037e43dfc8428583f1c72dcd62d0001001341e3da05520ee6b2802028480101439558d502c16dc8b7653426f214deab76586ca2c56f23ab98b48b5267eed8bc0003",
                )
                .unwrap(),
                HexBinary::from_hex(
                    "b5ee9c72010208010001960009460337fe6dc93dc682754931204fc9a7a6ec02a1e8fd53acc28be08ac067d1fbfdb1000501241011ef55aafffffffd0203040502a09bc7a987000000008401015f804f000000000200000000000000000000000066a50b4c000015f140e43800000015f140e438014d4af0b900047b4c0147870601478393c40000000800000000000001ee060728480101fcf00788fd51e3bc42a1d5379da3afdb1b31b17a6eb86ff5ee158202c1f02d770001284801017c88382b17de0be074a0053d1e056a7271d7b7c23b0c4b469a8da990b0da32d3000428480101115a57b53b90f009f12446afc450de68834146b01f014d96cbdb07ad69dc529000010098000015f140d4f5c4014787075bfa5a9407caa943497759faf565d96fe8d4d675ed72a964cec001eb440b335a3eae995fe699666a48287cf910c5f2a0818b14a1a0a20b5a83ae97135e6436ae0098000015f140d4f5c4015f804ec3ee48fcfb1951c41df4cc1ceb1b68e7dabc32182746e36bcb3090f14bad0af4cdd2b41c9af274705c299d8c79406ae3c328623ac1d192c91c3b3caddcd4627c",
                )
                .unwrap(),
            ],
        })
        .unwrap(),
        funds: vec![],
    });
    app.app.execute(owner.clone(), msg).unwrap();

    // verify tx block
    let msg = cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
        contract_addr: bridge_addr.to_string(),
        msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
            tx_boc: HexBinary::from_hex("b5ee9c72010211010003450003b5705cd4593d741fc359b579f9b05aeffcc9ab7cc7b788924957f2431d43d1d0f75000015f140d4f5c1a36f23584818716259d1b12d4a1a60b8c6f4df29976e6721a4eff339660d9870000015f14079684366a50b4a000546c4674280102030201e004050082725bc12430b7094c9649826b0550b887a42522f80b11bbda296bc4a0ae8f3c3a82a7307e385b80e3e85fa6aed19a5cf24d56d64f18e3628d26fe9f745f2f48d8110217044389021cc38c186a3fd4110f1001b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f77570001735164f5d07f0d66d5e7e6c16bbff326adf31ede2249255fc90c750f4743dd5021cc38c00612b38a00002be2814e5e04cd4a1686c0060201dd08090118af35dc850000000000000000070285ffff8002ffebe3c28cde5b8ecb40e97d7ef35c1ca6f6f20f434a1c58dbc497e8476984844e2000000000cd4a326e299beee0c4cf91a62d47583c7745120351acd2a5810e0d0101200a0101200b00c948000b9a8b27ae83f86b36af3f360b5dff99356f98f6f112492afe4863a87a3a1eeb000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a10206bd4400608235a00002be281a9eb84cd4a16946a993b6d800000000000000040019fe0002e6a2c9eba0fe1acdabcfcd82d77fe64d5be63dbc44924abf9218ea1e8e87bab004e144dd2dfc339aa2639312e1cd6f5d35a03924795906c1a4d156fb124e7097a000015f140d4f5c366a50b4a600c02bda64c12a300000000000000011f886e35000000000000000000000000000027100000000066a5193714cdf7706267c8d316a3ac1e3ba28901a8d66952c08002ffebe3c28cde5b8ecb40e97d7ef35c1ca6f6f20f434a1c58dbc497e8476984900d0e0043800536affe20d6af471ee32332b9ebfa93e271bd0d924f1e3bc5f0dce4860a07c5100000009e468f4c15a16c0000000000000000f400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98a23504c40d3cc0000000000040000000000053a3508ffc6a9d6d2c621844cb7fe15d925624c39aabb75f4d0c992e64911db9641504ccc").unwrap(),
            tx_proof: HexBinary::from_hex("b5ee9c72010210010002fb00094603c3ee48fcfb1951c41df4cc1ceb1b68e7dabc32182746e36bcb3090f14bad0af4001f01241011ef55aafffffffd0203040502a09bc7a987000000008401015f804e000000000200000000000000000000000066a50b4a000015f140d4f5c0000015f140d4f5c44d4af0b900047b4c0147870601478393c40000000800000000000001ee06072848010167650f78a9eae9494f5a3a0b4ffa657c3de887d6657294db573277968937141a000128480101cc14e21c72a1dc48a74e278dd596d7b0ca90e8c2ca12b1f89b3f62b729b86a17001e23894a33f6fdc540aa39b755ffae32b04c425d2c46501e831aba8f7fb18c819bb6b60a37477855ba839d64291c2e272d37bed587debc8653dbb1f6342747bb3447681533dfbf4008090a0098000015f140c5b3840147870601160693e59aeda77a71c6a85c3206e624c2b876589909f1046434be0495ec8db37737bf2aea702ee9a183ee2b94b6f35aaebd83180fc2a3ccce2c36e7320ba90098000015f140c5b381015f804d60808aef9591c0f3065403bb60937021674a049c05e60624539d2f1b0e508179a206b4ebab6fd3727aa62830bfe6274ec01efb73bad093fcf7da98136591c04d28480101f266622e77d2b020b40dda4ec40655bbe76865265760a595147c6d4958617137000928480101747427c412a5ddbbc3933125b9b2956d23c18c48b511a51311aa10ac6b2529dc000a21079b167f1a0b220960d8b3f8d00c0d22a3bf4b9a8b27ae83f86b36af3f360b5dff99356f98f6f112492afe4863a87a3a1eea6c46742505cd4593d741fc359b579f9b05aeffcc9ab7cc7b788924957f2431d43d1d0f75a000000af8a06a7ae09b119d0a0e0f284801014518eb72f99744912489062273d29c4efa158e17c0ab7c7188438932f55a9824000328480101f6532afe25bf35a0e13fef84792cb35fde2c1fcdbed78ce321413413bdce75df00060082725bc12430b7094c9649826b0550b887a42522f80b11bbda296bc4a0ae8f3c3a82a7307e385b80e3e85fa6aed19a5cf24d56d64f18e3628d26fe9f745f2f48d811").unwrap(),
        })
        .unwrap(),
        funds: vec![],
    });
    let res = app.app.execute(owner.clone(), msg).unwrap();
    println!("Res: {:?}", res);
    let sender_balance = app.query_balance(owner.clone(), denom.clone()).unwrap();
    assert_eq!(sender_balance.u128(), 10000);

    app.app
        .execute(
            owner.clone(),
            cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
                contract_addr: bridge_addr.to_string(),
                msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::BridgeToTon(
                    BridgeToTonMsg {
                        denom: "EQAX_18eFGby3HZaB0vr95rg5Te3kHoaUOLG3iS_QjtMJNg9".to_string(), // usdt contract
                        timeout: None,
                        to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                    },
                ))
                .unwrap(),
                funds: vec![coin(1000, denom.clone())],
            }),
        )
        .unwrap();
    let sender_balance = app.query_balance(owner.clone(), denom.clone()).unwrap();
    assert_eq!(sender_balance.u128(), 9000);
}

// FIXME: Wrong canonical address length
// #[test]
// fn test_bridge_ton_to_orai_with_fee() {
//     let MockApp {
//         mut app,
//         owner,
//         validator_addr,
//         bridge_addr,
//         cw20_addr,
//         ..
//     } = new_mock_app();
//     // update bridge adapter contract
//     app.execute(
//         owner.clone(),
//         bridge_addr.clone(),
//         &tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
//             validator_contract_addr: None,
//             bridge_adapter: Some("EQCWH9kCKpCTpswaygq-Ah7h-1vH3xZ3gJq7-SM6ZkYiOgHH".to_string()),
//             relayer_fee_token: None,
//             token_fee_receiver: None,
//             relayer_fee_receiver: None,
//             relayer_fee: None,
//             swap_router_contract: None,
//             token_fee: None,
//         },
//         &[],
//     )
//     .unwrap();

//     let tx_boc = HexBinary::from_hex("b5ee9c72010211010003450003b57961fd9022a9093a6cc1aca0abe021ee1fb5bc7df1677809abbf9233a6646223a00002b5df4ae0c41591328d8b3673d4b795f57c789e145481d3b1d2413af77a28086813032f2cf0c00002b5df4527ec1668fba29000546e2689c80102030201e0040500827298457e3ebcfa880e4a67df0d88c69cca63a7ca8de9234ad23dbe051f586d8469b9aa5df59ef1ad564d84695fd6c9182ef92b205953a7da224579e187466403bb02170446c91cef574c186c1fe8110f1001b1680026199d4cf9ecc6786607ea6ab5d07ebb2b7300531ce1d62713126b93e9b547fb002587f6408aa424e9b306b282af8087b87ed6f1f7c59de026aefe48ce9991888e91cef574c00612b38a000056bbe9008b04cd1f743ac0060201dd08090118af35dc850000000000000000070285ffff800e538276dbe580f97e140d56c7a695e8a9e7a641d8379b1f6b8da49a100d42f8444e2000000000cd1f574c299beee0c4cf91a62d47583c7745120351acd2a5810e0d0101200a0101200b00c948012c3fb2045521274d983594157c043dc3f6b78fbe2cef013577f24674cc8c44750005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63391cd590dc00608235a000056bbe95c1884cd1f74526a993b6d800000000000000040019fe004b0fec81154849d3660d65055f010f70fdade3ef8b3bc04d5dfc919d3323111d30010926e9e39e0b6f991fe801420858017cc708d639ef898187dc61b9eac89901a00002b5df4ae0c43668fba29600c02bda64c12a300000000000000071f886e350000000000000000000000000000271000000000668faba614cdf7706267c8d316a3ac1e3ba28901a8d66952c0800e538276dbe580f97e140d56c7a695e8a9e7a641d8379b1f6b8da49a100d42f8500d0e00438002dca7653b4c646d7d66400ffc787b1f6d70e8a404e3438ee55e6376927dfb19d00000009e47c28c3d09000000000000000000f200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98a23504c40d3cc0000000000040000000000044acf306fc0346e061272572316da3988492c51b2df2a48f0fae17327c722d09c41504ccc").unwrap();

//     let tx_proof = HexBinary::from_hex("b5ee9c7201021a010003e800094603eb26d6f3d075f89f8ad8bb011a6814ec6a283c697cbcc0ca2450eaad97a06327002501241011ef55aaffffff110203040502a09bc7a98700000000800102a6fa0e0000000102000000008000000000000000668fba2900002b5df4ae0c4000002b5df4ae0c4d28b29c140008f0420252443f025228dbc400000007000000000000002e06072848010169134a3a596b68d647965f54a94d98fea6b8cdca27f61d5f8117859ae80f71460003284801017bdcfc2172b6c9e181490a9960cd7b90b44dd129ebc618a416f60c0144298d38002423894a33f6fde8a3fae01eb649213b6347684dcdd1bea74a224138fe572d3b2b41d156d02415ea2e404dd0ee02412f2a7791d30abd074ec16256fa83cd5376d4b0fbcfddf8df4008090a009800002b5df49eca040252443fadd1d2b79fce4fb274d594057b44704ff4a09d783433498401d7a3268998344d7d92a3baba00a520556b90da5731b089013a8491278cf99870417e8178cd5028009800002b5df49eca0a02a6fa0dad0968c77acc29e9847831a33ecf1005ea8b189a9fc33fc9a640718d23639083a9e2bf177215b1ed5d4f8737860e81c9f3ae9669024ecaedde03957abf34359a2848010126a390200ef92244737858b673f1eddffd1c0b96fc85d754efbdaab26a28ec2c001c284801019a90185f6324eab6c87c27f5a8ff53ea2a129b6b519e9d95f81c4dbb648b0cdf001c2109a0773e1bc20b220b6903b9f0de100c0d2209101d4c77b50e0f28480101d6b60f4f983236f3b9e6a5b198a318ecb28bb7b5b1df54711cdaf4142f300e85001928480101df692049ca7bbaa2a47bf4008e104f7f11838553b7883c8dc39d865f57145524001322091015c153d910112209100cb12509121328480101812da7fe1eab36c72bf9174ae0dfd6ed4477180a7090ed81503a3e27a3aa9fe9000d284801016a53739349b426fbaa9093865a46d4986f351f269f1a24e94596ab9afea86f05001322091008bed0f514152848010173151c552b62a83c7ff320b32184eb6219e12e8d6aaba1c40061cec12c5ca742000a22091004e5ff19161722a3be07f6408aa424e9b306b282af8087b87ed6f1f7c59de026aefe48ce9991888e8dc4d138b2c3fb2045521274d983594157c043dc3f6b78fbe2cef013577f24674cc8c44754000002b5df4ae0c41371344e40181928480101f8c0756de82229a358f03b021ba0c2cd31ddfcf3b220192248fd05b7ddfc425f001228480101f070dea8890cc35e161d5c3019d8e8b195dff34ffd2ef60b975727645296d338000600827298457e3ebcfa880e4a67df0d88c69cca63a7ca8de9234ad23dbe051f586d8469b9aa5df59ef1ad564d84695fd6c9182ef92b205953a7da224579e187466403bb").unwrap();

//     let opcode =
//         HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
//             .unwrap();
//     let token_denom = "EQBynBO23ywHy_CgarY9NK9FTz0yDsG82PtcbSTQgGoXwiuA";
//     let packet_timeout_timestamp = 1720691622u64;

//     let mut block_info = app.app.block_info();
//     block_info.time = Timestamp::from_seconds(packet_timeout_timestamp - 10);
//     app.app.set_block(block_info);
//     // update fee
//     app.app
//         .execute(
//             owner.clone(),
//             cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//                 contract_addr: bridge_addr.to_string(),
//                 msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
//                     validator_contract_addr: None,
//                     bridge_adapter: None,
//                     relayer_fee_token: Some(AssetInfo::Token {
//                         contract_addr: cw20_addr.clone(),
//                     }),
//                     token_fee_receiver: None,
//                     relayer_fee_receiver: None,
//                     relayer_fee: Some(Uint128::from(1000u128)),
//                     swap_router_contract: None,
//                     token_fee: Some(vec![TokenFee {
//                         token_denom: token_denom.to_string(),
//                         ratio: Ratio {
//                             nominator: 1,
//                             denominator: 1000,
//                         },
//                     }]),
//                 })
//                 .unwrap(),
//                 funds: vec![],
//             }),
//         )
//         .unwrap();

//     app.app
//         .execute(
//             owner.clone(),
//             cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//                 contract_addr: bridge_addr.to_string(),
//                 msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
//                     UpdatePairMsg {
//                         denom: token_denom.to_string(),
//                         local_asset_info: AssetInfo::Token {
//                             contract_addr: Addr::unchecked(cw20_addr.clone()),
//                         },
//                         remote_decimals: 6,
//                         local_asset_info_decimals: 6,
//                         opcode,
//                         token_origin: 529034805,
//                     },
//                 ))
//                 .unwrap(),
//                 funds: vec![],
//             }),
//         )
//         .unwrap();

//     // shard block with block hash
//     let block_hash =
//         HexBinary::from_hex("eb26d6f3d075f89f8ad8bb011a6814ec6a283c697cbcc0ca2450eaad97a06327")
//             .unwrap();

//     // set verified for simplicity
//     app.app
//         .execute(
//             owner.clone(),
//             cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//                 contract_addr: validator_addr.to_string(),
//                 msg: to_json_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
//                     root_hash: block_hash,
//                     seq_no: 1,
//                 })
//                 .unwrap(),
//                 funds: vec![],
//             }),
//         )
//         .unwrap();

//     app.app
//         .execute(
//             owner.clone(),
//             cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//                 contract_addr: bridge_addr.to_string(),
//                 msg: to_json_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
//                     tx_proof,
//                     tx_boc,
//                 })
//                 .unwrap(),
//                 funds: vec![],
//             }),
//         )
//         .unwrap();

//     // try query fee balance
//     let relayer_balance: BalanceResponse = app
//         .app
//         .wrap()
//         .query_wasm_smart(
//             cw20_addr.clone(),
//             &cw20_base::msg::QueryMsg::Balance {
//                 address: "relayer_fee".to_string(),
//             },
//         )
//         .unwrap();
//     assert_eq!(relayer_balance.balance, Uint128::from(1000u128));
//     let token_fee_balance: BalanceResponse = app
//         .app
//         .wrap()
//         .query_wasm_smart(
//             cw20_addr.clone(),
//             &cw20_base::msg::QueryMsg::Balance {
//                 address: "token_fee".to_string(),
//             },
//         )
//         .unwrap();
//     assert_eq!(token_fee_balance.balance, Uint128::from(100u128));
// }

// TODO
// #[test]
// fn test_read_ack_transaction() {
//     let mut deps = mock_dependencies();
//     let deps_mut = deps.as_mut();
//     let seq = 1u64;
//     let mut cell_builder = CellBuilder::new();

//     // case 1: invalid no-op -> invalid packet
//     cell_builder
//         .store_slice(&RECEIVE_PACKET_MAGIC_NUMBER.to_be_bytes())
//         .unwrap();

//      let res =
// }
