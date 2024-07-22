use std::str::FromStr;

use cosmwasm_std::{
    attr, coin,
    testing::{mock_dependencies, mock_env, mock_info},
    to_binary, Addr, Api, CanonicalAddr, CosmosMsg, HexBinary, SubMsg, Timestamp, Uint128, WasmMsg,
};

use cw20::{BalanceResponse, Cw20ExecuteMsg, Cw20ReceiveMsg};
use cw_multi_test::Executor;

use oraiswap::{asset::AssetInfo, router::RouterController};
use tonbridge_bridge::{
    amount::Amount,
    msg::{
        BridgeToTonMsg, ChannelResponse, ExecuteMsg, InstantiateMsg, QueryMsg as BridgeQueryMsg,
        UpdatePairMsg,
    },
    state::{Config, MappingMetadata, Ratio, TokenFee},
};
use tonbridge_parser::{
    transaction_parser::{RECEIVE_PACKET_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER},
    types::{BridgePacketData, Status},
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
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
//             msg: to_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
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
            msg: to_binary(&BridgeToTonMsg {
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
            msg: to_binary(&BridgeToTonMsg {
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
            msg: to_binary(&BridgeToTonMsg {
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

// FIXME: Wrong canonical address length
// #[test]
// fn test_bridge_ton_to_orai_with_fee() {
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
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
//     // update fee
//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: bridge_addr.to_string(),
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
//                 validator_contract_addr: None,
//                 bridge_adapter: None,
//                 relayer_fee_token: Some(AssetInfo::Token {
//                     contract_addr: cw20_addr.clone(),
//                 }),
//                 token_fee_receiver: None,
//                 relayer_fee_receiver: None,
//                 relayer_fee: Some(Uint128::from(1000u128)),
//                 swap_router_contract: None,
//                 token_fee: Some(vec![TokenFee {
//                     token_denom: token_denom.to_string(),
//                     ratio: Ratio {
//                         nominator: 1,
//                         denominator: 1000,
//                     },
//                 }]),
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
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

//     // shard block with block hash
//     let block_hash =
//         HexBinary::from_hex("eb26d6f3d075f89f8ad8bb011a6814ec6a283c697cbcc0ca2450eaad97a06327")
//             .unwrap();

//     // set verified for simplicity
//     app.execute(
//         owner.clone(),
//         cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
//             contract_addr: validator_addr.to_string(),
//             msg: to_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
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
//             msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
//                 tx_proof,
//                 tx_boc,
//             })
//             .unwrap(),
//             funds: vec![],
//         }),
//     )
//     .unwrap();

//     // try query fee balance
//     let relayer_balance: BalanceResponse = app
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
