use std::time::{SystemTime, UNIX_EPOCH};

use cosmwasm_std::{Addr, BlockInfo, HexBinary, Timestamp, Uint128};
use cosmwasm_testing_util::ContractWrapper;
use cw20::Cw20Coin;
use derive_more::{Deref, DerefMut};
use oraiswap::asset::AssetInfo;

pub fn new_mock_app() -> MockApp {
    MockApp::new(None)
}

pub fn new_mock_app_with_boc(key_block_boc: HexBinary) -> MockApp {
    MockApp::new(Some(key_block_boc))
}

#[derive(Deref, DerefMut)]
pub struct MockApp {
    #[deref]
    #[deref_mut]
    pub app: cosmwasm_testing_util::MockApp,
    pub owner: Addr,
    pub validator_addr: Addr,
    pub bridge_addr: Addr,
    pub cw20_addr: Addr,
    pub token_factory_addr: Addr,
}

impl MockApp {
    pub fn new(boc: Option<HexBinary>) -> Self {
        let mut app = cosmwasm_testing_util::MockApp::new(&[]);
        app.app.set_block(BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            chain_id: "Oraichain".to_string(),
        });
        let admin = Addr::unchecked("admin");

        let validator_id = app.upload(Box::new(ContractWrapper::new_with_empty(
            cw_tonbridge_validator::contract::execute,
            cw_tonbridge_validator::contract::instantiate,
            cw_tonbridge_validator::contract::query,
        )));
        let bridge_id = app.upload(Box::new(ContractWrapper::new_with_empty(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        )));
        let cw20_id = app.upload(Box::new(ContractWrapper::new_with_empty(
            cw20_base::contract::execute,
            cw20_base::contract::instantiate,
            cw20_base::contract::query,
        )));
        let bridge_cw20_balance = Uint128::from(10000000000000001u64);

        let validator_addr = app
            .instantiate(
                validator_id,
                admin.clone(),
                &tonbridge_validator::msg::InstantiateMsg { boc: boc },
                &vec![],
                "validator",
            )
            .unwrap();

        let token_factory_addr = app.create_tokenfactory(admin.clone()).unwrap();

        let bridge_addr = app
            .instantiate(
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
                    token_factory_addr: Some(token_factory_addr.clone()),
                    osor_entrypoint_contract: Addr::unchecked("osor_entrypoint_contract"),
                },
                &vec![],
                "bridge",
            )
            .unwrap();

        let cw20_addr = app
            .instantiate(
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
                "dummy",
            )
            .unwrap();

        Self {
            app,
            owner: admin,
            validator_addr,
            bridge_addr,
            cw20_addr,
            token_factory_addr,
        }
    }
}
