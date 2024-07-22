use std::time::{SystemTime, UNIX_EPOCH};

use cosmwasm_std::{Addr, BlockInfo, Empty, Timestamp, Uint128};
use cw20::Cw20Coin;
use cw_multi_test::{App, AppBuilder, Contract, ContractWrapper, Executor};
use oraiswap::asset::AssetInfo;

fn validator_contract() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        cw_tonbridge_validator::contract::execute,
        cw_tonbridge_validator::contract::instantiate,
        cw_tonbridge_validator::contract::query,
    );
    Box::new(contract)
}

fn bridge_contract() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        crate::contract::execute,
        crate::contract::instantiate,
        crate::contract::query,
    );
    Box::new(contract)
}

fn dummy_cw20_contract() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        cw20_base::contract::execute,
        cw20_base::contract::instantiate,
        cw20_base::contract::query,
    );
    Box::new(contract)
}

fn new_app() -> App {
    let mut app = AppBuilder::new().build(|_router, _, _storage| {});
    app.set_block(BlockInfo {
        height: 1,
        time: Timestamp::from_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
        chain_id: "Oraichain".to_string(),
    });
    app
}

pub fn new_mock_app() -> MockApp {
    MockApp::new()
}

pub struct MockApp {
    pub app: App,
    pub owner: Addr,
    pub validator_addr: Addr,
    pub bridge_addr: Addr,
    pub cw20_addr: Addr,
}

impl MockApp {
    pub fn new() -> Self {
        let mut app = new_app();
        let admin = Addr::unchecked("admin");
        let validator_contract = validator_contract();
        let bridge_contract = bridge_contract();
        let dummy_cw20_contract = dummy_cw20_contract();
        let validator_id = app.store_code(validator_contract);
        let bridge_id = app.store_code(bridge_contract);
        let cw20_id = app.store_code(dummy_cw20_contract);
        let bridge_cw20_balance = Uint128::from(10000000000000001u64);

        let validator_addr = app
            .instantiate_contract(
                validator_id,
                admin.clone(),
                &tonbridge_validator::msg::InstantiateMsg { boc: None },
                &vec![],
                "validator".to_string(),
                None,
            )
            .unwrap();

        let bridge_addr = app
            .instantiate_contract(
                bridge_id,
                admin.clone(),
                &tonbridge_bridge::msg::InstantiateMsg {
                    validator_contract_addr: validator_addr.clone(),
                    bridge_adapter: "EQAE8anZidQFTKcsKS_98iDEXFkvuoa1YmVPxQC279zAoV7R".to_string(),
                    relayer_fee_token: AssetInfo::NativeToken {
                        denom: "orai".to_string(),
                    },
                    token_fee_receiver: Addr::unchecked("token_fee"),
                    relayer_fee_receiver: Addr::unchecked("relayer_fee"),
                    relayer_fee: None,
                    swap_router_contract: "router".to_string(),
                    token_factory_addr: None,
                },
                &vec![],
                "bridge".to_string(),
                None,
            )
            .unwrap();

        let cw20_addr = app
            .instantiate_contract(
                cw20_id,
                admin.clone(),
                &cw20_base::msg::InstantiateMsg {
                    name: "Dummy".to_string(),
                    symbol: "DUMMY".to_string(),
                    decimals: 6,
                    initial_balances: vec![{
                        Cw20Coin {
                            address: bridge_addr.to_string(),
                            amount: bridge_cw20_balance,
                        }
                    }],
                    mint: None,
                    marketing: None,
                },
                &vec![],
                "dummy".to_string(),
                None,
            )
            .unwrap();

        Self {
            app,
            owner: admin,
            validator_addr,
            bridge_addr,
            cw20_addr,
        }
    }
}
