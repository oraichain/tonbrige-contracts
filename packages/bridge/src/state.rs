use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint128;
use oraiswap::asset::AssetInfo;
use tonbridge_parser::types::Bytes32;

#[cw_serde]
pub struct MappingMetadata {
    /// asset info on local chain. Can be either cw20 or native
    pub asset_info: AssetInfo,
    pub remote_decimals: u8,
    pub asset_info_decimals: u8,
    pub opcode: Bytes32,
}

#[cw_serde]
#[derive(Default)]
pub struct ChannelState {
    pub outstanding: Uint128,
    pub total_sent: Uint128,
}
