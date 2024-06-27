use cosmwasm_std::{to_binary, Addr, HexBinary, Uint128};
use cw_multi_test::Executor;
use oraiswap::{asset::AssetInfo, router::RouterController};
use tonbridge_bridge::{
    msg::{DeletePairMsg, PairQuery, QueryMsg as BridgeQueryMsg, UpdatePairMsg},
    parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id},
    state::{Config, MappingMetadata, Ratio, TokenFee},
};
use tonbridge_parser::to_bytes32;

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

    // register failed, no admin
    app.execute(
        Addr::unchecked("alice"),
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
                    opcode: opcode.clone(),
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
                    local_channel_id: "channel-0".to_string(),
                    denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
                    local_asset_info: AssetInfo::Token {
                        contract_addr: Addr::unchecked(cw20_addr.clone()),
                    },
                    remote_decimals: 6,
                    local_asset_info_decimals: 6,
                    opcode: opcode.clone(),
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();

    // query mapping
    let ibc_denom = get_key_ics20_ibc_denom(
        &parse_ibc_wasm_port_id(bridge_addr.as_str()),
        "channel-0",
        "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl",
    );
    let res: PairQuery = app
        .wrap()
        .query_wasm_smart(
            bridge_addr.clone(),
            &BridgeQueryMsg::PairMapping {
                key: ibc_denom.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        res,
        PairQuery {
            key: ibc_denom.clone(),
            pair_mapping: MappingMetadata {
                asset_info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(cw20_addr.clone()),
                },
                remote_decimals: 6,
                asset_info_decimals: 6,
                opcode: to_bytes32(&opcode).unwrap()
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
                    local_channel_id: "channel-0".to_string(),
                    denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
                },
            ))
            .unwrap(),
            funds: vec![],
        }),
    )
    .unwrap();
}
