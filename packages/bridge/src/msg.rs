use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128};
use cw20::Cw20ReceiveMsg;
use cw20_ics20_msg::amount::Amount;
use oraiswap::asset::AssetInfo;

#[cw_serde]
pub struct InstantiateMsg {
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
        opcode: HexBinary, // in hex form
        validator_contract_addr: String,
    },
    UpdateMappingPair(UpdatePairMsg),
    BridgeToTon(BridgeToTonMsg),
    Receive(Cw20ReceiveMsg),
    SubmitBridgeToTonInfo {
        data: HexBinary,
    },
    UpdateOwner {
        new_owner: Addr,
    },
    UpdateConfig {
        relayer_fee_token: Option<AssetInfo>,
        token_fee_receiver: Option<Addr>,
        relayer_fee_receiver: Option<Addr>,
        relayer_fee: Option<Uint128>,
        swap_router_contract: Option<String>,
    },
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

#[cw_serde]
pub struct BridgeToTonMsg {
    pub local_channel_id: String, // default channel-0
    pub to: String,
    pub denom: String,
    pub crc_src: u32,
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
    /// Returns the details of the name channel, error if not created.
    #[returns(ChannelResponse)]
    ChannelStateData { channel_id: String },
}

// We define a custom struct for each query response
#[cw_serde]
pub struct ConfigResponse {
    pub owner: Option<String>,
}

/// The format for sending an ics20 packet.
/// Proto defined here: https://github.com/cosmos/cosmos-sdk/blob/v0.42.0/proto/ibc/applications/transfer/v1/transfer.proto#L11-L20
/// This is compatible with the JSON serialization
#[cw_serde]
#[derive(Default)]
pub struct Ics20Packet {
    /// amount of tokens to transfer is encoded as a string
    pub amount: Uint128,
    /// the token denomination to be transferred
    pub denom: String,
    /// the recipient address on the destination chain
    pub receiver: String,
    /// the sender address
    pub sender: String,
    /// optional memo
    pub memo: Option<String>,
}

impl Ics20Packet {
    pub fn new<T: Into<String>>(
        amount: Uint128,
        denom: T,
        sender: &str,
        receiver: &str,
        memo: Option<String>,
    ) -> Self {
        Ics20Packet {
            denom: denom.into(),
            amount,
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            memo,
        }
    }
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
