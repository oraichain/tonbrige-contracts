use cosmwasm_std::Uint128;
use tonlib::{address::TonAddress, cell::CellBuilder};

use crate::{
    bridge::{ACK_MAGIC_NUMBER, RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER},
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
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())?; // opcode
    cell_builder.store_slice(&crc_src.to_be_bytes())?; // crc_src
    cell_builder.store_address(&TonAddress::from_base64_std(to)?)?; // receiver
    cell_builder.store_address(&TonAddress::from_base64_std(denom)?)?; // remote denom
    cell_builder.store_slice(&amount.to_be_bytes())?; // remote amount
    cell_builder.store_slice(&timeout_timestamp.to_be_bytes())?; // timeout timestamp

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

pub fn build_receive_packet_timeout_commitment(seq: u64) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_slice(&RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER.to_be_bytes())?; // opcode

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

pub fn build_ack_commitment(seq: u64) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_slice(&ACK_MAGIC_NUMBER.to_be_bytes())?; // opcode

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Uint128;

    use crate::helper::build_ack_commitment;

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
                147, 141, 120, 107, 189, 160, 37, 224, 20, 139, 119, 27, 41, 112, 235, 158, 243,
                86, 229, 168, 245, 240, 137, 105, 219, 215, 18, 219, 240, 56, 252, 91
            ]
        )
    }
    #[test]
    fn test_build_ack_commitment() {
        let commitment = build_ack_commitment(1).unwrap();
        assert_eq!(
            commitment,
            vec![
                179, 254, 186, 2, 145, 250, 132, 167, 133, 98, 70, 99, 164, 49, 39, 41, 170, 131,
                214, 113, 92, 87, 140, 74, 254, 68, 4, 123, 121, 0, 37, 237
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
                176, 40, 134, 153, 7, 174, 65, 132, 250, 22, 14, 89, 57, 48, 237, 114, 194, 57,
                158, 22, 197, 123, 38, 238, 56, 19, 59, 140, 221, 175, 42, 35
            ]
        )
    }
}
