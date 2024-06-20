use crate::types::Bytes32;

use super::types::ValidatorDescription;
use sha2::{Digest, Sha256};

pub const BLOCK_INFO_CELL: u32 = 0x9bc7a987;
pub const BLOCK_EXTRA_CELL: u16 = 0xcca5;
pub type ValidatorSet20 = [ValidatorDescription; 20];
pub type ValidatorSet32 = [ValidatorDescription; 32];
pub type ValidatorSet = Vec<ValidatorDescription>;

pub fn sha256(data: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn compute_node_id(public_key: Bytes32) -> Bytes32 {
    let mut data = vec![0xc6, 0xb4, 0x13, 0x48];
    data.extend_from_slice(&public_key);
    sha256(&data)
}
