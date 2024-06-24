use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdResult, Uint128, Uint256};
use tonlib::address::TonAddress as TonlibTonAddress;

pub type Bytes32 = [u8; 32];
pub type Bytes4 = [u8; 4];
pub type Address = [u8; 20];
pub type ValidatorSet = Vec<ValidatorDescription>;

#[cw_serde]
#[derive(Copy, Default)]
pub struct ValidatorDescription {
    pub c_type: u8,
    pub weight: u64,
    pub adnl_addr: Bytes32,
    pub pubkey: Bytes32,
    pub node_id: Bytes32,
    // mapping(bytes32 => bool) verified;
}

#[cw_serde]
pub struct Vdata {
    pub node_id: Bytes32,
    pub r: Bytes32,
    pub s: Bytes32,
}

#[cw_serde]
pub struct VdataHex {
    pub node_id: HexBinary,
    pub r: HexBinary,
    pub s: HexBinary,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct CachedCell {
    pub prefix_length: u128,
    pub hash: Bytes32,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct VerifiedBlockInfo {
    pub verified: bool,
    pub seq_no: u32,
    pub start_lt: u64,
    pub end_lt: u64,
    pub new_hash: Bytes32,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct CellData {
    pub special: bool,
    pub refs: [usize; 4],
    pub cursor: usize,
    pub cursor_ref: u8,

    pub hashes: [Bytes32; 4],
    pub level_mask: u32,
    pub depth: [u16; 4],
    pub cell_type: u8,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct CellSerializationInfo {
    pub d1: u8,
    pub d2: u8,
    pub special: bool,
    pub level_mask: u32,
    pub with_hashes: bool,
    pub hashes_offset: usize,
    pub depth_offset: usize,
    pub data_offset: usize,
    pub data_len: usize,
    pub data_with_bits: bool,
    pub refs_offset: usize,
    pub refs_cnt: usize,
    pub end_offset: usize,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct TonAddress {
    pub hash: Bytes32,
    pub wc: u8,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct RawCommonMessageInfo {
    pub msg_type: Uint256,
    pub ihr_disabled: bool,
    pub bounce: bool,
    pub bounced: bool,
    pub src: TonAddress,
    pub dest: TonAddress,
    // value RawCurrencyCollection
    pub value: Bytes32,
    pub ihr_fee: Bytes32,
    pub fwd_fee: Bytes32,
    pub created_lt: Uint256,
    pub created_at: Uint256,
    pub import_fee: Bytes32,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct Message {
    pub info: RawCommonMessageInfo,
    pub body_idx: usize,
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct MessagesHeader {
    pub has_in_message: bool,
    pub has_out_messages: bool,
    pub in_message: Message,
    pub out_messages: [Message; 5],
}

#[cw_serde]
#[derive(Copy, Default)]
pub struct TransactionHeader {
    pub check_code: u8,
    pub address_hash: Bytes32,
    pub lt: u64,
    pub prev_trans_hash: Bytes32,
    pub prev_trans_lt: u64,
    pub time: u32,
    pub out_mesages_count: u32,
    pub old_status: u8,
    pub new_status: u8,
    pub fees: Bytes32,
    pub messages: MessagesHeader,
}

#[cw_serde]
#[derive(Default)]
pub struct PacketData {
    // should change to cannonical addr, same as Address with 20 bytes
    pub receiving_address: String,
    // pub receiving_token: AssetInfo,
    pub amount: Uint256,
}

#[cw_serde]
#[derive(Default)]
pub struct KeyBlockValidators {
    pub previous: ValidatorSet,
    pub current: ValidatorSet,
    pub next: ValidatorSet,
}

#[derive(Default, Clone)]
pub struct BridgePacketDataRaw {
    pub src_denom: TonlibTonAddress,
    pub src_channel: Vec<u8>,
    pub amount: String,
    pub dest_denom: Vec<u8>,
    pub dest_channel: Vec<u8>,
    pub dest_receiver: Vec<u8>,
    pub orai_address: Vec<u8>, // use as recovery address
}

impl BridgePacketDataRaw {
    pub fn to_pretty(self) -> StdResult<BridgePacketData> {
        Ok(BridgePacketData {
            src_denom: self.src_denom.to_string(),
            src_channel: String::from_utf8(self.src_channel)?,
            amount: Uint128::from_str(&self.amount)?,
            dest_denom: String::from_utf8(self.dest_denom)?,
            dest_channel: String::from_utf8(self.dest_channel)?,
            dest_receiver: String::from_utf8(self.dest_receiver)?,
            orai_address: String::from_utf8(self.orai_address)?,
        })
    }
}

#[cw_serde]
#[derive(Default)]
pub struct BridgePacketData {
    pub src_denom: String,
    pub src_channel: String,
    pub amount: Uint128,
    pub dest_denom: String,
    pub dest_channel: String,
    pub dest_receiver: String,
    pub orai_address: String, // use as recovery address
}
