use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128, Uint256};
use cw20::Cw20ReceiveMsg;
use oraiswap::asset::AssetInfo;

use crate::{
    amount::Amount,
    state::{MappingMetadata, TokenFee},
};

#[cw_serde]
pub struct InstantiateMsg {
    pub validator_contract_addr: Addr,
    pub bridge_adapter: String,
    pub relayer_fee_token: AssetInfo,
    pub token_fee_receiver: Addr,
    pub relayer_fee_receiver: Addr,
    pub relayer_fee: Option<Uint128>,
    pub swap_router_contract: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    ReadTransaction {
        tx_proof: HexBinary,
        tx_boc: HexBinary, // in hex form
    },
    UpdateMappingPair(UpdatePairMsg),
    DeleteMappingPair(DeletePairMsg),
    BridgeToTon(BridgeToTonMsg),
    Receive(Cw20ReceiveMsg),
    UpdateOwner {
        new_owner: Addr,
    },
    UpdateConfig {
        validator_contract_addr: Option<Addr>,
        bridge_adapter: Option<String>,
        relayer_fee_token: Option<AssetInfo>,
        token_fee_receiver: Option<Addr>,
        relayer_fee_receiver: Option<Addr>,
        relayer_fee: Option<Uint128>,
        swap_router_contract: Option<String>,
        token_fee: Option<Vec<TokenFee>>,
    },
    // ProcessTimeoutSendPacket {
    //     masterchain_header_proof: HexBinary,
    //     tx_proof_unreceived: HexBinary,
    //     tx_boc: HexBinary, // in hex form
    // },
}

#[cw_serde]
pub struct UpdatePairMsg {
    /// native denom of the remote chain. Eg: orai
    pub denom: String,
    /// asset info of the local chain.
    pub local_asset_info: AssetInfo,
    pub remote_decimals: u8,
    pub local_asset_info_decimals: u8,
    pub opcode: HexBinary,
    pub token_origin: u32,
}

#[cw_serde]
pub struct DeletePairMsg {
    /// native denom of the remote chain. Eg: orai
    pub denom: String,
}

#[cw_serde]
pub struct BridgeToTonMsg {
    pub to: String,
    pub denom: String,
    pub timeout: Option<u64>,
}

/// We currently take no arguments for migrations
#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(String)]
    Owner {},
    #[returns(crate::state::Config)]
    Config {},
    #[returns(bool)]
    IsTxProcessed { tx_hash: HexBinary },
    /// Returns the details of the name channel, error if not created.
    #[returns(ChannelResponse)]
    ChannelStateData {},
    #[returns(crate::state::Ratio)]
    TokenFee { remote_token_denom: String },
    #[returns(PairQuery)]
    PairMapping { key: String },
    #[returns(Uint256)]
    SendPacketCommitment { seq: u64 },
    #[returns(Uint256)]
    AckCommitment { seq: u64 },
}

#[cw_serde]
pub struct PairQuery {
    pub key: String,
    pub pair_mapping: MappingMetadata,
}

#[cw_serde]
pub struct ChannelResponse {
    /// How many tokens we currently have pending over this channel
    pub balances: Vec<Amount>,
    /// The total number of tokens that have been sent over this channel
    /// (even if many have been returned, so balance is low)
    pub total_sent: Vec<Amount>,
}

#[cw_serde]
pub struct FeeData {
    pub deducted_amount: Uint128,
    pub token_fee: Amount,
    pub relayer_fee: Amount,
}
