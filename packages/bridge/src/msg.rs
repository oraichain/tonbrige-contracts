use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use oraiswap::asset::AssetInfo;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    ReadTransaction {
        tx_boc: HexBinary,    // in hex form
        block_boc: HexBinary, // in hex form
        opcode: HexBinary,    // in hex form
        validator_contract_addr: String,
    },
    UpdateMappingPair(UpdatePairMsg),
}

#[cw_serde]
pub struct UpdatePairMsg {
    pub local_channel_id: String,
    /// native denom of the remote chain. Eg: orai
    pub denom: String,
    /// asset info of the local chain.
    pub local_asset_info: AssetInfo,
    pub remote_decimals: u8,
    pub local_asset_info_decimals: u8,
}

/// We currently take no arguments for migrations
#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},
    #[returns(bool)]
    IsTxProcessed { tx_hash: HexBinary },
}

// We define a custom struct for each query response
#[cw_serde]
pub struct ConfigResponse {
    pub owner: Option<String>,
}
