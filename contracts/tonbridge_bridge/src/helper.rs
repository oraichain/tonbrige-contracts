use std::str::FromStr;

use cosmwasm_std::Uint128;

use tonbridge_parser::{
    transaction_parser::{
        RECEIVE_PACKET_MAGIC_NUMBER, RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER,
    },
    types::Status,
};
use tonlib::{address::TonAddress, cell::CellBuilder};

use crate::error::ContractError;

pub fn is_expired(now: u64, timestamp: u64) -> bool {
    now > timestamp
}

pub fn build_bridge_to_ton_commitment(
    seq: u64,
    token_origin: u32,
    sender_raw: &[u8],
    remote_receiver: &str,
    remote_denom: &str,
    amount: Uint128,
    timeout_timestamp: u64,
) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())?; // opcode
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_slice(&token_origin.to_be_bytes())?; // crc_src
    cell_builder.store_slice(&amount.to_be_bytes())?; // remote amount
    cell_builder.store_slice(&timeout_timestamp.to_be_bytes())?; // timeout timestamp

    cell_builder.store_address(&TonAddress::from_str(remote_receiver)?)?; // receiver
    cell_builder.store_address(&TonAddress::from_str(remote_denom)?)?; // remote denom

    let mut sender_ref = CellBuilder::new();
    sender_ref.store_slice(&(sender_raw.len() as u8).to_be_bytes())?;
    sender_ref.store_slice(sender_raw)?;
    cell_builder.store_reference(&sender_ref.build()?.to_arc())?; //the first ref is sender address

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

pub fn build_ack_commitment(
    seq: u64,
    token_origin: u32,
    remote_amount: Uint128,
    timeout_timestamp: u64,
    receiver: &[u8],
    remote_denom: &str,
    remote_sender: &str,
    status: Status,
) -> Result<Vec<u8>, ContractError> {
    let mut cell_builder = CellBuilder::new();
    cell_builder.store_slice(&RECEIVE_PACKET_MAGIC_NUMBER.to_be_bytes())?; // opcode
    cell_builder.store_slice(&seq.to_be_bytes())?; // seq
    cell_builder.store_slice(&token_origin.to_be_bytes())?; // crc_src
    cell_builder.store_slice(&remote_amount.to_be_bytes())?; // remote amount
    cell_builder.store_slice(&timeout_timestamp.to_be_bytes())?; // timeout timestamp

    // store receiver
    cell_builder.store_slice(&(receiver.len() as u8).to_be_bytes())?;
    cell_builder.store_slice(receiver)?;

    cell_builder.store_address(&TonAddress::from_str(remote_denom)?)?; // remote denom

    cell_builder.store_u8(2, status as u8)?; // status

    // store remote sender
    cell_builder.store_reference(
        &CellBuilder::new()
            .store_address(&TonAddress::from_str(remote_sender)?)?
            .build()?
            .to_arc(),
    )?;

    let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
    Ok(commitment)
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::{testing::mock_dependencies, Api, Uint128};
    use tonbridge_parser::types::Status;

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
        let seq: u64 = 1;
        let token_origin = 0x1f886e35;
        let remote_amount = Uint128::from(1000u128);
        let timeout_timestamp = 12345678;
        let receiver = mock_dependencies()
            .api
            .addr_canonicalize("orai1hvr9d72r5um9lvt0rpkd4r75vrsqtw6yujhqs2")
            .unwrap();
        let remote_denom = "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT";
        let remote_sender = "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT";
        let status = Status::Success;

        let commitment = build_ack_commitment(
            seq,
            token_origin,
            remote_amount,
            timeout_timestamp,
            receiver.as_slice(),
            remote_denom,
            remote_sender,
            status,
        )
        .unwrap();
        assert_eq!(
            commitment,
            vec![
                30, 195, 51, 117, 201, 166, 123, 203, 42, 97, 207, 254, 143, 162, 253, 154, 26,
                140, 22, 217, 121, 127, 114, 244, 194, 141, 25, 207, 42, 81, 170, 26
            ]
        )
    }

    #[test]
    fn test_build_bridge_to_ton_commitment() {
        let sender_raw = mock_dependencies()
            .as_ref()
            .api
            .addr_canonicalize("orai1hvr9d72r5um9lvt0rpkd4r75vrsqtw6yujhqs2")
            .unwrap();
        let commitment = build_bridge_to_ton_commitment(
            1,
            1576711861,
            sender_raw.as_slice(),
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            Uint128::from(10000000000u128),
            1719945916,
        )
        .unwrap();
        assert_eq!(
            commitment,
            vec![
                242, 70, 65, 240, 144, 22, 6, 195, 224, 167, 252, 122, 176, 172, 13, 126, 188, 134,
                55, 69, 9, 216, 250, 98, 51, 125, 103, 181, 130, 117, 208, 103
            ]
        )
    }
}
