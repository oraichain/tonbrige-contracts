use cosmwasm_schema::{cw_serde, QueryResponses};

use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
  ReadTransaction {
    tx_boc: String, // in hex form
    block_boc: String, // in hex form
    opcode: String, // in hex form
    ton_token: String,
    validator_contract_addr: String,
  }
}

/// We currently take no arguments for migrations
#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},
}

// We define a custom struct for each query response
#[cw_serde]
pub struct ConfigResponse {
    pub owner: Addr,
    pub rewarder: Addr,
    pub oracle_addr: Addr,
    pub factory_addr: Addr,
    pub base_denom: String,
}
