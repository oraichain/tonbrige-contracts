use std::str::FromStr;

use cosmwasm_std::{to_json_binary, Addr, Api, CosmosMsg, StdError, Uint128, WasmMsg};

use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw_storage_plus::KeyDeserialize;
use oraiswap::asset::{Asset, AssetInfo};
use tonbridge_parser::{
    transaction_parser::{RECEIVE_PACKET_MAGIC_NUMBER, SEND_TO_TON_MAGIC_NUMBER},
    types::Status,
};
use tonlib::{
    address::TonAddress,
    cell::{Cell, CellBuilder},
};

use crate::error::ContractError;

pub fn is_expired(now: u64, timestamp: u64) -> bool {
    now > timestamp
}

pub fn denom_to_asset_info(api: &dyn Api, denom: &str) -> AssetInfo {
    if let Ok(contract_addr) = api.addr_validate(denom) {
        AssetInfo::Token { contract_addr }
    } else {
        AssetInfo::NativeToken {
            denom: denom.to_string(),
        }
    }
}

pub fn parse_asset_info_denom(asset_info: &AssetInfo) -> String {
    match asset_info {
        AssetInfo::Token { contract_addr } => format!("cw20:{}", contract_addr),
        AssetInfo::NativeToken { denom } => denom.to_string(),
    }
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

#[allow(clippy::too_many_arguments)]
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

pub fn build_mint_asset_msg(
    token_factory: Option<Addr>,
    asset: &Asset,
    receiver: String,
) -> Result<CosmosMsg, ContractError> {
    let msg = match &asset.info {
        AssetInfo::NativeToken { denom } => {
            if token_factory.is_none() {
                return Err(ContractError::Std(StdError::generic_err(
                    "Missing factory contract",
                )));
            }
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: token_factory.unwrap().to_string(),
                msg: to_json_binary(&tokenfactory::msg::ExecuteMsg::MintTokens {
                    denom: denom.to_owned(),
                    amount: asset.amount,
                    mint_to_address: receiver,
                })?,
                funds: vec![],
            })
        }
        AssetInfo::Token { contract_addr } => {
            Cw20Contract(contract_addr.to_owned()).call(Cw20ExecuteMsg::Mint {
                recipient: receiver,
                amount: asset.amount,
            })?
        }
    };

    Ok(msg)
}

pub fn build_burn_asset_msg(
    token_factory: Option<Addr>,
    asset: &Asset,
    from_address: String,
) -> Result<CosmosMsg, ContractError> {
    let msg = match &asset.info {
        AssetInfo::NativeToken { denom } => {
            if token_factory.is_none() {
                return Err(ContractError::Std(StdError::generic_err(
                    "Missing factory contract",
                )));
            }
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: token_factory.unwrap().to_string(),
                msg: to_json_binary(&tokenfactory::msg::ExecuteMsg::BurnTokens {
                    denom: denom.to_owned(),
                    amount: asset.amount,
                    burn_from_address: from_address,
                })?,
                funds: vec![],
            })
        }
        AssetInfo::Token { contract_addr } => {
            Cw20Contract(contract_addr.to_owned()).call(Cw20ExecuteMsg::Burn {
                amount: asset.amount,
            })?
        }
    };

    Ok(msg)
}

pub fn parse_memo(cell: &Option<Cell>) -> Result<String, ContractError> {
    if let Some(cell) = cell {
        let mut memo = vec![];
        cell.load_buffer(&mut memo)?;
        Ok(String::from_vec(memo)?)
    } else {
        Ok(String::default())
    }
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::{CanonicalAddr, Uint128};
    use tonbridge_parser::types::Status;

    use crate::helper::build_ack_commitment;

    use super::{build_bridge_to_ton_commitment, is_expired};

    #[test]
    fn test_is_expired() {
        assert_eq!(is_expired(1, 2), false);
        assert_eq!(is_expired(2, 1), true);
        assert_eq!(is_expired(1, 1), false);
    }

    #[test]
    fn test_build_ack_commitment() {
        let seq: u64 = 1;
        let token_origin = 0x1f886e35;
        let remote_amount = Uint128::from(1000u128);
        let timeout_timestamp = 12345678;
        let receiver_raw: Vec<u8> = vec![
            23, 12, 3, 5, 13, 30, 10, 3, 20, 28, 27, 5, 31, 12, 11, 15, 3, 1, 22, 13, 21, 3, 30,
            20, 12, 3, 16, 0, 11, 14, 26, 4,
        ];
        let receiver = CanonicalAddr::from(receiver_raw);
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
                109, 202, 88, 184, 101, 35, 125, 237, 237, 215, 90, 74, 220, 121, 216, 139, 90, 95,
                155, 76, 168, 211, 162, 152, 162, 203, 236, 176, 39, 121, 37, 197
            ]
        )
    }

    #[test]
    fn test_build_bridge_to_ton_commitment() {
        let sender_raw: Vec<u8> = vec![
            23, 12, 3, 5, 13, 30, 10, 3, 20, 28, 27, 5, 31, 12, 11, 15, 3, 1, 22, 13, 21, 3, 30,
            20, 12, 3, 16, 0, 11, 14, 26, 4,
        ];

        let commitment = build_bridge_to_ton_commitment(
            1,
            1576711861,
            &sender_raw,
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT",
            Uint128::from(10000000000u128),
            1719945916,
        )
        .unwrap();
        assert_eq!(
            commitment,
            vec![
                80, 173, 167, 0, 148, 212, 70, 12, 2, 222, 170, 71, 218, 190, 218, 221, 132, 153,
                132, 21, 151, 233, 206, 238, 145, 171, 199, 119, 174, 253, 14, 98
            ]
        )
    }
}
