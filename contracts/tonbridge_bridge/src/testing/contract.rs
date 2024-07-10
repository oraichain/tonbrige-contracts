use std::str::FromStr;

use cosmwasm_std::{
    coin, from_binary,
    testing::{mock_dependencies, mock_env},
    to_binary, Addr, HexBinary, Uint128,
};
use cw20_ics20_msg::amount::Amount;
use cw_multi_test::Executor;
use oraiswap::{
    asset::{Asset, AssetInfo},
    router::RouterController,
};
use tonbridge_bridge::{
    msg::{ChannelResponse, DeletePairMsg, PairQuery, QueryMsg as BridgeQueryMsg, UpdatePairMsg},
    state::{Config, MappingMetadata, Ratio, TimeoutSendPacket, TokenFee},
};
use tonbridge_parser::{
    to_bytes32, transaction_parser::SEND_PACKET_TIMEOUT_MAGIC_NUMBER, EMPTY_HASH,
};
use tonlib::{
    address::TonAddress,
    cell::CellBuilder,
    responses::{AnyCell, MaybeRefData, MessageType, TransactionMessage},
};

use crate::{
    channel::{decrease_channel_balance, increase_channel_balance},
    contract::{build_timeout_send_packet_refund_msgs, is_tx_processed, query},
    error::ContractError,
    state::{PROCESSED_TXS, TIMEOUT_RECEIVE_PACKET, TIMEOUT_SEND_PACKET},
};

use super::mock::{new_mock_app, MockApp};

#[test]
fn test_instantiate_contract() {
    let MockApp {
        app,
        owner,
        bridge_addr,
        ..
    } = new_mock_app();

    let config: Config = app
        .wrap()
        .query_wasm_smart(bridge_addr.clone(), &BridgeQueryMsg::Config {})
        .unwrap();
    assert_eq!(
        config,
        Config {
            validator_contract_addr: Addr::unchecked("contract0"),
            bridge_adapter: "EQAE8anZidQFTKcsKS_98iDEXFkvuoa1YmVPxQC279zAoV7R".to_string(),
            relayer_fee_token: AssetInfo::NativeToken {
                denom: "orai".to_string()
            },
            relayer_fee: Uint128::zero(),
            token_fee_receiver: Addr::unchecked("token_fee"),
            relayer_fee_receiver: Addr::unchecked("relayer_fee"),
            swap_router_contract: RouterController("router".to_string())
        }
    );
    let _owner: Addr = app
        .wrap()
        .query_wasm_smart(bridge_addr.clone(), &BridgeQueryMsg::Owner {})
        .unwrap();
    assert_eq!(owner, _owner);
}

#[test]
fn test_update_owner() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        ..
    } = new_mock_app();

    // update failed, not admin
    app.execute(
        Addr::unchecked("alice"),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateOwner {
                new_owner: Addr::unchecked("alice"),
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap_err();

    // update success
    app.execute(
        owner,
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateOwner {
                new_owner: Addr::unchecked("alice"),
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();
    let _owner: Addr = app
        .wrap()
        .query_wasm_smart(bridge_addr.clone(), &BridgeQueryMsg::Owner {})
        .unwrap();
    assert_eq!(_owner, Addr::unchecked("alice"));
}

#[test]
fn test_update_config() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        ..
    } = new_mock_app();

    // update failed, not admin
    app.execute(
        Addr::unchecked("alice"),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: None,
                bridge_adapter: None,
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
    .unwrap_err();

    // update success
    app.execute(
        owner,
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: Some(Addr::unchecked("contract1")),
                bridge_adapter: Some(
                    "DQAE8anZidQFTKcsKS_98iDEXFkvuoa1YmVPxQC279zAoV7R".to_string(),
                ),
                relayer_fee_token: Some(AssetInfo::NativeToken {
                    denom: "atom".to_string(),
                }),
                relayer_fee: Some(Uint128::one()),
                token_fee_receiver: Some(Addr::unchecked("new_token_fee")),
                relayer_fee_receiver: Some(Addr::unchecked("new_relayer_fee")),
                swap_router_contract: Some("new_router".to_string()),
                token_fee: None,
            })
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    let config: Config = app
        .wrap()
        .query_wasm_smart(bridge_addr.clone(), &BridgeQueryMsg::Config {})
        .unwrap();
    assert_eq!(
        config,
        Config {
            validator_contract_addr: Addr::unchecked("contract1"),
            bridge_adapter: "DQAE8anZidQFTKcsKS_98iDEXFkvuoa1YmVPxQC279zAoV7R".to_string(),
            relayer_fee_token: AssetInfo::NativeToken {
                denom: "atom".to_string()
            },
            relayer_fee: Uint128::one(),
            token_fee_receiver: Addr::unchecked("new_token_fee"),
            relayer_fee_receiver: Addr::unchecked("new_relayer_fee"),
            swap_router_contract: RouterController("new_router".to_string())
        }
    );
}

#[test]
fn test_update_token_fee() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        ..
    } = new_mock_app();

    app.execute(
        owner,
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateConfig {
                validator_contract_addr: None,
                bridge_adapter: None,
                relayer_fee_token: None,
                token_fee_receiver: None,
                relayer_fee_receiver: None,
                relayer_fee: None,
                swap_router_contract: None,
                token_fee: Some(vec![TokenFee {
                    token_denom: "orai".to_string(),
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

    let ratio: Ratio = app
        .wrap()
        .query_wasm_smart(
            bridge_addr.clone(),
            &BridgeQueryMsg::TokenFee {
                remote_token_denom: "orai".to_string(),
            },
        )
        .unwrap();

    assert_eq!(
        ratio,
        Ratio {
            nominator: 1,
            denominator: 1000,
        },
    )
}

#[test]
fn test_register_mapping_pair() {
    let MockApp {
        mut app,
        owner,
        bridge_addr,
        cw20_addr,
        ..
    } = new_mock_app();
    let opcode =
        HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let ibc_denom = "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl";

    // register failed, no admin
    app.execute(
        Addr::unchecked("alice"),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                UpdatePairMsg {
                    denom: ibc_denom.to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode: opcode.clone(),
                    token_origin: 529034805,
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap_err();

    // register success
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                UpdatePairMsg {
                    denom: ibc_denom.to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode: opcode.clone(),
                    token_origin: 529034805,
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // query mapping

    let res: PairQuery = app
        .wrap()
        .query_wasm_smart(
            bridge_addr.clone(),
            &BridgeQueryMsg::PairMapping {
                key: ibc_denom.to_string(),
            },
        )
        .unwrap();
    assert_eq!(
        res,
        PairQuery {
            key: ibc_denom.to_string(),
            pair_mapping: MappingMetadata {
                asset_info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(cw20_addr.clone()),
                },
                remote_decimals: 6,
                asset_info_decimals: 6,
                opcode: to_bytes32(&opcode).unwrap(),
                token_origin: 529034805
            }
        }
    );

    // try remove
    app.execute(
        owner.clone(),
        cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
            contract_addr: bridge_addr.to_string(),
            msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::DeleteMappingPair(
                DeletePairMsg {
                    denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();
}

#[test]
fn test_update_channel_balance() {
    let mut deps = mock_dependencies();
    let denom = "ton";
    // try increase
    increase_channel_balance(deps.as_mut().storage, denom, Uint128::from(1000000u128)).unwrap();

    // after increase, query channel balance
    let state: ChannelResponse = from_binary(
        &query(
            deps.as_ref(),
            mock_env(),
            BridgeQueryMsg::ChannelStateData {},
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        state,
        ChannelResponse {
            balances: vec![Amount::Native(coin(1000000, denom))],
            total_sent: vec![Amount::Native(coin(1000000, denom))],
        }
    );

    // try decrease channel balance
    decrease_channel_balance(deps.as_mut().storage, denom, Uint128::from(500000u128)).unwrap();

    // after decrease, query channel balance
    let state: ChannelResponse = from_binary(
        &query(
            deps.as_ref(),
            mock_env(),
            BridgeQueryMsg::ChannelStateData {},
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        state,
        ChannelResponse {
            balances: vec![Amount::Native(coin(500000, denom))],
            total_sent: vec![Amount::Native(coin(1000000, denom))],
        }
    );

    // cannot decrease channel balance because not enough balances
    decrease_channel_balance(deps.as_mut().storage, denom, Uint128::from(600000u128)).unwrap_err();
}

#[test]
fn test_build_timeout_send_packet_refund_msgs() {
    let mut deps = mock_dependencies();
    let deps_mut = deps.as_mut();
    let mut out_msg: MaybeRefData<TransactionMessage> = MaybeRefData::default();
    let env = mock_env();
    let latest_timestamp = env.block.time.seconds();
    let bridge_addr = "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string();
    let sender = "orai1rchnkdpsxzhquu63y6r4j4t57pnc9w8ehdhedx";
    let seq = 1u64;

    // case 1: out msg is invalid -> empty res
    let res = build_timeout_send_packet_refund_msgs(
        deps_mut.storage,
        deps_mut.api,
        &deps_mut.querier,
        out_msg.clone(),
        bridge_addr.clone(),
        latest_timestamp as u32,
    )
    .unwrap();
    assert_eq!(res.len(), 0);

    let mut transaction_message = TransactionMessage::default();
    transaction_message.info.msg_type = MessageType::ExternalOut as u8;
    transaction_message.info.src = TonAddress::from_str(&bridge_addr.clone()).unwrap();
    let mut any_cell = AnyCell::default();
    let mut cell_builder = CellBuilder::new();
    cell_builder
        .store_slice(&SEND_PACKET_TIMEOUT_MAGIC_NUMBER.to_be_bytes())
        .unwrap();
    // sequence
    cell_builder.store_slice(&seq.to_be_bytes()).unwrap();
    let cell = cell_builder.build().unwrap();
    any_cell.cell = cell;
    transaction_message.body.cell_ref = Some((Some(any_cell.clone()), None));
    out_msg.data = Some(transaction_message.clone());

    // case 2: timeout packet not found -> no-op
    let res = build_timeout_send_packet_refund_msgs(
        deps_mut.storage,
        deps_mut.api,
        &deps_mut.querier,
        out_msg.clone(),
        bridge_addr.clone(),
        latest_timestamp as u32,
    )
    .unwrap();
    assert_eq!(res.len(), 0);

    // case 3: packet has not timed out yet
    TIMEOUT_SEND_PACKET
        .save(
            deps_mut.storage,
            seq,
            &TimeoutSendPacket {
                local_refund_asset: Asset {
                    info: AssetInfo::NativeToken {
                        denom: "orai".to_string(),
                    },
                    amount: Uint128::zero(),
                },
                sender: bridge_addr.clone(),
                timeout_timestamp: latest_timestamp + 1,
            },
        )
        .unwrap();

    let err = build_timeout_send_packet_refund_msgs(
        deps_mut.storage,
        deps_mut.api,
        &deps_mut.querier,
        out_msg.clone(),
        bridge_addr.clone(),
        latest_timestamp as u32,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), ContractError::NotExpired {}.to_string());

    // case 4: happy case
    TIMEOUT_SEND_PACKET
        .save(
            deps_mut.storage,
            seq,
            &TimeoutSendPacket {
                local_refund_asset: Asset {
                    info: AssetInfo::NativeToken {
                        denom: "orai".to_string(),
                    },
                    amount: Uint128::zero(),
                },
                sender: sender.to_string(),
                timeout_timestamp: latest_timestamp - 1,
            },
        )
        .unwrap();
    let res = build_timeout_send_packet_refund_msgs(
        deps_mut.storage,
        deps_mut.api,
        &deps_mut.querier,
        out_msg.clone(),
        bridge_addr.clone(),
        latest_timestamp as u32,
    )
    .unwrap();
    assert_eq!(res.len(), 1);
}

#[test]
fn test_is_tx_processed() {
    let deps = mock_dependencies();
    let result = is_tx_processed(deps.as_ref(), HexBinary::from(EMPTY_HASH)).unwrap();
    assert_eq!(result, false);

    let mut deps = mock_dependencies();
    PROCESSED_TXS
        .save(deps.as_mut().storage, &EMPTY_HASH, &true)
        .unwrap();
    let result = is_tx_processed(deps.as_ref(), HexBinary::from(EMPTY_HASH)).unwrap();
    assert_eq!(result, true);
}
