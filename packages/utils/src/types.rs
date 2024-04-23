use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint256;

pub type Bytes32 = [u8; 32];
pub type Bytes4 = [u8; 4];
pub type Address = [u8; 20];

#[cw_serde]
pub struct BagOfCellsInfo {
    pub magic: Bytes4,
    pub root_count: Uint256,
    pub cell_count: Uint256,
    pub absent_count: Uint256,
    pub ref_byte_size: Uint256,
    pub offset_byte_size: Uint256,
    pub has_index: bool,
    pub has_roots: bool,
    pub has_crc32c: bool,
    pub has_cache_bits: bool,
    pub roots_offset: Uint256,
    pub index_offset: Uint256,
    pub data_offset: Uint256,
    pub data_size: Uint256,
    pub total_size: Uint256,
    pub root_idx: Uint256,
}

#[cw_serde]
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
pub struct CachedCell {
    pub prefix_length: Uint256,
    pub hash: Bytes32,
}

#[cw_serde]
pub struct VerifiedBlockInfo {
    pub verified: bool,
    pub seq_no: u32,
    pub start_lt: u64,
    pub end_lt: u64,
    pub new_hash: Bytes32,
}

#[cw_serde]
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
pub struct CellSerializationInfo {
    pub d1: u8,
    pub d2: u8,
    pub special: bool,
    pub level_mask: u32,
    pub with_hashes: bool,
    pub hashes_offset: Uint256,
    pub depth_offset: Uint256,
    pub data_offset: Uint256,
    pub data_len: Uint256,
    pub data_with_bits: bool,
    pub refs_offset: Uint256,
    pub refs_cnt: Uint256,
    pub end_offset: Uint256,
}

pub struct TonAddress {
    pub hash: Bytes32,
    pub wc: u8,
}

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

pub struct Message {
    pub info: RawCommonMessageInfo,
    pub body_idx: Uint256,
}

pub struct MessagesHeader {
    pub has_in_message: bool,
    pub has_out_messages: bool,
    pub in_message: Message,
    pub out_messages: [Message; 5],
}

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

pub struct TestData {
    pub eth_address: Address,
    pub amount: Uint256,
}
