use super::types::{Bytes32, Bytes4};

pub const OPCODE_1: Bytes32 = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
pub const OPCODE_2: Bytes32 = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
pub const EMPTY_HASH: Bytes32 = [0; 32];
pub const BOC_IDX: Bytes4 = [0x68, 0xff, 0x65, 0xf3];
pub const BOC_IDX_CRC32C: Bytes4 = [0xac, 0xc3, 0xa7, 0x28];
pub const BOC_GENERIC: Bytes4 = [0xb5, 0xee, 0x9c, 0x72];
pub const ORDINARY_CELL: u8 = 255;
pub const PRUNNED_BRANCH_CELL: u8 = 1;
pub const LIBRARY_CELL: u8 = 2;
pub const MERKLE_PROOF_CELL: u8 = 3;
pub const MERKLE_UPDATE_CELL: u8 = 4;
