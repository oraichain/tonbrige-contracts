use std::time::{SystemTime, UNIX_EPOCH};

use cosmwasm_std::{coins, Addr, BlockInfo, HexBinary, Timestamp};
use cosmwasm_testing_util::ContractWrapper;
use derive_more::{Deref, DerefMut};

pub fn new_mock_app() -> MockApp {
    MockApp::new(None)
}

#[derive(Deref, DerefMut)]
pub struct MockApp {
    #[deref]
    #[deref_mut]
    pub app: cosmwasm_testing_util::MultiTestMockApp,
    pub owner: Addr,
    pub validator_addr: Addr,
    pub bridge_addr: Addr,
    pub cw20_addr: Addr,
    pub token_factory_addr: Addr,
}

impl MockApp {
    pub fn new(boc: Option<HexBinary>) -> Self {
        let (mut app, accounts) = cosmwasm_testing_util::MultiTestMockApp::new(&[(
            "admin",
            &coins(100_000_000_000_000u128, "orai"),
        )]);
        let admin = Addr::unchecked(&accounts[0]);
        app.inner_mut().set_block(BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            chain_id: "Oraichain".to_string(),
        });

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

        let validator_addr = app
            .instantiate(
                validator_id,
                admin.clone(),
                &tonbridge_validator::msg::InstantiateMsg { boc },
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
                    token_fee_receiver: Addr::unchecked("token_fee"),
                    relayer_fee_receiver: Addr::unchecked("relayer_fee"),
                    swap_router_contract: "router".to_string(),
                    token_factory_addr: Some(token_factory_addr.clone()),
                    osor_entrypoint_contract: Addr::unchecked("osor_entrypoint_contract"),
                },
                &vec![],
                "bridge",
            )
            .unwrap();

        let cw20_addr = app.create_token(admin.as_str(), "DUMMY", 10000000000000001u128);
        app.set_token_balances(
            admin.as_str(),
            &[("DUMMY", &[(bridge_addr.as_str(), 10000000000000001u128)])],
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
