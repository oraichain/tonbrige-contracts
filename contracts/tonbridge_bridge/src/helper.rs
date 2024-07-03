use cosmwasm_std::Uint128;
use tonlib::{address::TonAddress, cell::CellBuilder};

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
    cell_builder.store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())?; // opcode
    cell_builder.store_slice(&crc_src.to_be_bytes())?; // crc_src
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_address(&TonAddress::from_base64_std(to)?)?; // receiver
    cell_builder.store_address(&TonAddress::from_base64_std(denom)?)?; // remote denom
    cell_builder.store_slice(&amount.to_be_bytes())?; // remote amount
    cell_builder.store_slice(&timeout_timestamp.to_be_bytes())?; // timeout timestamp

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

pub fn build_receive_packet_timeout_commitment(seq: u64) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_slice(&RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER.to_be_bytes())?; // opcode
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Uint128;

    use super::{
        build_bridge_to_ton_commitment, build_receive_packet_timeout_commitment, is_expired,
    };

    #[test]
    fn test_is_expired() {
        assert_eq!(is_expired(1, 2), false);
        assert_eq!(is_expired(2, 1), true);
        assert_eq!(is_expired(1, 1), false);
    }

    #[test]
    fn test_build_receive_packet_timeout_commitment() {
        let commitment = build_receive_packet_timeout_commitment(1).unwrap();
        assert_eq!(
            commitment,
            vec![
                31, 112, 103, 53, 231, 62, 248, 14, 0, 155, 123, 249, 55, 209, 63, 240, 63, 255,
                84, 147, 234, 64, 167, 198, 41, 72, 6, 213, 27, 47, 165, 189
            ]
        )
    }

    #[test]
    fn test_build_bridge_to_ton_commitment() {
        let commitment = build_bridge_to_ton_commitment(
            1,
            1576711861,
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            Uint128::from(10000000000u128),
            1719945916,
        )
        .unwrap();
        assert_eq!(
            commitment,
            vec![
                119, 193, 142, 10, 121, 185, 151, 96, 213, 92, 38, 8, 35, 164, 206, 127, 169, 152,
                124, 138, 154, 53, 213, 232, 194, 103, 121, 126, 40, 150, 236, 133
            ]
        )
    }
}
