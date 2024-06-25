use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use oraiswap::{asset::AssetInfo, router::RouterController};
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

#[cw_serde]
pub struct TokenFee {
    pub token_denom: String,
    pub ratio: Ratio,
}

#[cw_serde]
pub struct RelayerFee {
    pub prefix: String,
    pub fee: Uint128,
}

#[cw_serde]
pub struct Ratio {
    pub nominator: u64,
    pub denominator: u64,
}

#[cw_serde]
pub struct Config {
    pub validator_contract_addr: Addr,
    pub bridge_adapter: String, // bridge adapter on TON
    pub relayer_fee_token: AssetInfo,
    pub relayer_fee: Uint128, // This fee depends on the network type, not token type decimals of relayer fee should always be 10^6
    pub token_fee_receiver: Addr,
    pub relayer_fee_receiver: Addr,
    pub swap_router_contract: RouterController,
}

#[cw_serde]
pub struct SendPacket {
    pub sequence: u64,
    pub to: String,
    pub denom: String,
    pub amount: Uint128,
    pub crc_src: u32,
}
