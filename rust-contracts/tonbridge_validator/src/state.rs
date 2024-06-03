use cosmwasm_std::{Order, Storage};
use cw_storage_plus::{Item, Map};

use cw_controllers::Admin;
use tonbridge_parser::types::{Bytes32, ValidatorDescription, VerifiedBlockInfo};

use crate::validator::Validator;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");
pub const SIGNED_BLOCKS: Map<&[u8], bool> = Map::new("signed_blocks");
pub const VERIFIED_BLOCKS: Map<&Bytes32, VerifiedBlockInfo> = Map::new("verified_blocks");

pub const VALIDATOR: Item<Validator> = Item::new("validator");
pub const SIGNATURE_VALIDATOR_SET: Map<u64, ValidatorDescription> =
    Map::new("signature_validator_set");
pub const SIGNATURE_CANDIDATE_VALIDATOR: Map<u64, ValidatorDescription> =
    Map::new("signature_candidate_validator");

pub fn get_signature_candidate_validators(storage: &dyn Storage) -> Vec<ValidatorDescription> {
    SIGNATURE_CANDIDATE_VALIDATOR
        .range(storage, None, None, Order::Ascending)
        .into_iter()
        .map(|item| item.unwrap().1)
        .collect()
}

pub fn get_signature_validator_set(storage: &dyn Storage) -> Vec<ValidatorDescription> {
    SIGNATURE_VALIDATOR_SET
        .range(storage, None, None, Order::Ascending)
        .into_iter()
        .map(|item| item.unwrap().1)
        .collect()
}

pub fn reset_signature_candidate_validators(storage: &mut dyn Storage) -> () {
    SIGNATURE_CANDIDATE_VALIDATOR.clear(storage);
}

pub fn reset_signature_validator_set(storage: &mut dyn Storage) -> () {
    SIGNATURE_VALIDATOR_SET.clear(storage);
}
