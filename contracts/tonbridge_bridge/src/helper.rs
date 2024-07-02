use cosmwasm_std::{StdResult, Uint128};
use tonlib::{
    address::TonAddress,
    cell::{CellBuilder, TonCellError},
};

use crate::{
    bridge::{RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER},
    error::ContractError,
};

pub fn is_expired(now: u64, timestamp: u64) -> bool {
    now > timestamp
}

pub fn build_bridge_to_ton_commitment(
    seq: u64,
    crc_src: u32,
    to: &str,
    denom: &str,
    amount: Uint128,
    timeout_timestamp: u64,
) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_bits(32, &SEND_TO_TON_MAGIC_NUMBER.to_be_bytes().to_vec())?; // opcode
    cell_builder.store_bits(32, &crc_src.to_be_bytes().to_vec())?; // crc_src
    cell_builder.store_bits(64, &seq.to_be_bytes().to_vec())?; // seq
    cell_builder.store_address(&TonAddress::from_base64_std(to)?)?; // receiver
    cell_builder.store_address(&TonAddress::from_base64_std(denom)?)?; // remote denom
    cell_builder.store_bits(128, &amount.to_be_bytes().to_vec())?; // remote amount
    cell_builder.store_bits(64, &timeout_timestamp.to_be_bytes().to_vec())?; // timeout timestamp
    let mut cell = cell_builder.build()?;
    // cell_type is not is_exotic
    cell.is_exotic = false;
    let commitment: Vec<u8> = cell.cell_hash()?;
    Ok(commitment)
}

pub fn build_receive_packet_timeout_commitment(seq: u64) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_bits(
        32,
        &RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER.to_be_bytes().to_vec(),
    )?; // opcode
    cell_builder.store_bits(64, &seq.to_be_bytes().to_vec())?; // seq
    let mut cell = cell_builder.build()?;
    // cell_type is not is_exotic
    cell.is_exotic = false;
    let commitment: Vec<u8> = cell.cell_hash()?;

    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use super::is_expired;

    #[test]
    fn test_is_expired() {
        assert_eq!(is_expired(1, 2), false);
        assert_eq!(is_expired(2, 1), true);
        assert_eq!(is_expired(1, 1), false);
    }
}
