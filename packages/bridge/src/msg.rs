use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary, Uint128};
use cw20::Cw20ReceiveMsg;
use cw20_ics20_msg::amount::Amount;
use oraiswap::asset::AssetInfo;

use crate::state::{MappingMetadata, ReceivePacket, TokenFee};

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
    ProcessTimeoutSendPacket {
        masterchain_header_proof: HexBinary,
        tx_proof_unreceived: HexBinary,
        tx_boc: HexBinary, // in hex form
    },
    ProcessTimeoutRecievePacket {
        receive_packet: HexBinary,
    },
    Acknowledgment {
        tx_proof: HexBinary,
        tx_boc: HexBinary, // in hex form
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
    pub opcode: HexBinary,
}

#[cw_serde]
pub struct DeletePairMsg {
    pub local_channel_id: String,
    /// native denom of the remote chain. Eg: orai
    pub denom: String,
}

#[cw_serde]
pub struct BridgeToTonMsg {
    pub local_channel_id: String, // default channel-0
    pub to: String,
    pub denom: String,
    pub crc_src: u32,
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
    ChannelStateData { channel_id: String },
    #[returns(crate::state::Ratio)]
    TokenFee { remote_token_denom: String },
    #[returns(PairQuery)]
    PairMapping { key: String },
    #[returns(Vec<ReceivePacket>)]
    QueryTimeoutReceivePackets {},
}

#[cw_serde]
pub struct PairQuery {
    pub key: String,
    pub pair_mapping: MappingMetadata,
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
