use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Api, HexBinary, StdError, StdResult, Storage};
use tonbridge_parser::{
    compute_node_id,
    types::{Bytes32, KeyBlockValidators, ValidatorDescription, ValidatorSet, Vdata},
    EMPTY_HASH,
};
use tonlib::{
    cell::{BagOfCells, Cell, TonCellError},
    responses::{ConfigParam, ConfigParams, ConfigParamsValidatorSet},
};

use crate::{
    error::ContractError,
    state::{
        get_signature_candidate_validators, get_signature_validator_set,
        reset_signature_candidate_validators, validator_set, SIGNATURE_CANDIDATE_VALIDATOR,
        SIGNED_BLOCKS,
    },
};

pub const MESSAGE_PREFIX: [u8; 4] = [0x70, 0x6e, 0x0b, 0xc5];

pub trait ISignatureValidator {
    fn add_current_block_to_verified_set(
        &self,
        storage: &dyn Storage,
        root_h: Bytes32,
        validator_set: ValidatorSet,
    ) -> StdResult<Bytes32>;

    fn load_validator_from_config_param(
        config_params: &ConfigParams,
        param_number: u8,
    ) -> Result<ValidatorSet, ContractError>;

    fn load_validator_set(
        validator_infos: ConfigParamsValidatorSet,
    ) -> Result<ValidatorSet, ContractError>;

    fn verify_validators(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata],
    ) -> StdResult<u64>;

    fn parse_candidates_root_block(
        &mut self,
        storage: &mut dyn Storage,
        boc: &[u8],
    ) -> Result<(), ContractError>;

    fn is_signed_by_validator(
        &self,
        storage: &dyn Storage,
        node_id: Bytes32,
        root_h: Bytes32,
    ) -> bool;

    fn set_validator_set(&mut self, storage: &mut dyn Storage, api: &dyn Api)
        -> StdResult<Bytes32>;

    fn init_validators(&mut self, storage: &mut dyn Storage) -> StdResult<Bytes32>;

    fn get_validators_set_from_boc(
        &mut self,
        boc: &[u8],
    ) -> Result<KeyBlockValidators, ContractError>;
}

// need to deserialize from storage and better access directly from storage
#[cw_serde]
#[derive(Default)]
pub struct SignatureValidator {
    // used for validating key blocks?
    pub total_weight: u64,
    // sum of 100 largest weights of the validators for validating normal blocks, not key blocks
    pub sum_largest_total_weights: u64,
    candidates_total_weight: u64,
    // sum of 100 largest weights of the candidates
    sum_largest_candidates_total_weights: u64,
    pub root_hash: Bytes32,
    // check next validator updated
    has_candidate_next: bool,
    pub has_next: bool,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self::default()
    }

    fn parse_validators(
        &mut self,
        storage: &mut dyn Storage,
        validators: &mut KeyBlockValidators,
    ) -> StdResult<()> {
        // get total weight of main validator in current validator set
        validators.current.sort_by(|a, b| b.weight.cmp(&a.weight));
        let sum_100_main_current: u64 = validators
            .current
            .iter()
            .take(100)
            .map(|desc| desc.weight)
            .sum();

        // store all validators to candidate validator set
        let mut candidates_for_validator_set = get_signature_candidate_validators(storage)?;
        let mut j = candidates_for_validator_set.len();

        let mut total_validators: Vec<ValidatorDescription> = validators.previous.to_vec();
        total_validators.extend(validators.current.to_vec());
        total_validators.extend(validators.next.to_vec());

        for i in 0..total_validators.len() {
            // if the candidate is already in the list, we compare weight with the input
            if let Some(candidate) = candidates_for_validator_set.iter_mut().find(|val| {
                HexBinary::from(val.pubkey)
                    .to_hex()
                    .eq(&HexBinary::from(&total_validators[i].pubkey).to_string())
            }) {
                // old validator has less weight then new
                if candidate.weight < total_validators[i].weight {
                    self.candidates_total_weight += total_validators[i].weight;
                    self.candidates_total_weight -= candidate.weight;

                    std::mem::swap(candidate, &mut total_validators[i]);

                    candidate.node_id = compute_node_id(candidate.pubkey);
                }
            }
            // not found, we push a new default validator and update its info
            candidates_for_validator_set.push(ValidatorDescription::default());

            self.candidates_total_weight += total_validators[i].weight;
            candidates_for_validator_set[j] = total_validators[i];
            candidates_for_validator_set[j].node_id =
                compute_node_id(candidates_for_validator_set[j].pubkey);

            // increment size of validator set
            j += 1;
        }

        // store candidate validator
        self.sum_largest_candidates_total_weights = sum_100_main_current;

        // check  contain next_validator set
        self.has_candidate_next = !validators.next.is_empty();

        for (i, candidate) in candidates_for_validator_set.iter().enumerate() {
            SIGNATURE_CANDIDATE_VALIDATOR.save(storage, i as u64, candidate)?;
        }
        Ok(())
    }
}

impl ISignatureValidator for SignatureValidator {
    fn is_signed_by_validator(
        &self,
        storage: &dyn Storage,
        node_id: Bytes32,
        root_h: Bytes32,
    ) -> bool {
        SIGNED_BLOCKS
            .load(storage, &[node_id, root_h].concat())
            .unwrap_or_default()
    }

    fn add_current_block_to_verified_set(
        &self,
        storage: &dyn Storage,
        root_h: Bytes32,
        validator_set: ValidatorSet,
    ) -> StdResult<Bytes32> {
        let mut current_weight = 0;
        for j in 0..validator_set.len() {
            if self.is_signed_by_validator(storage, validator_set[j].node_id, root_h) {
                current_weight += validator_set[j].weight;
            }
        }

        if current_weight * 3 <= self.total_weight * 2 {
            return Err(StdError::generic_err("not enough votes"));
        }
        Ok(root_h)
    }

    fn verify_validators(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata],
    ) -> StdResult<u64> {
        if root_h == EMPTY_HASH || file_hash == EMPTY_HASH {
            return Err(StdError::generic_err("wrong root_hash or file_hash"));
        }

        let mut current_weight = 0u64;
        let mut message = MESSAGE_PREFIX.to_vec();
        message.extend_from_slice(&root_h);
        message.extend_from_slice(&file_hash);

        // this makes sure vdata doesn't contain replicated signatures
        let mut checked_validators: Vec<[u8; 32]> = vec![];
        for vdata_item in vdata {
            // 1. found validator
            if let Ok(validator) = validator_set().load(storage, &vdata_item.node_id) {
                if checked_validators.contains(&validator.pubkey) {
                    continue;
                }
                // we also increment current_weight in this case because it is valid to re-verify a block given a correct set of signatures
                if self.is_signed_by_validator(storage, validator.node_id, root_h) {
                    checked_validators.push(validator.pubkey);
                    current_weight += validator.weight;
                    continue;
                }

                // signature = r + s
                if api.ed25519_verify(
                    &message,
                    &[vdata_item.r, vdata_item.s].concat(),
                    &validator.pubkey,
                )? {
                    // update as verified
                    SIGNED_BLOCKS.save(storage, &[validator.node_id, root_h].concat(), &true)?;
                    checked_validators.push(validator.pubkey);
                    current_weight += validator.weight;
                }
            }
        }

        Ok(current_weight)
    }

    fn init_validators(&mut self, storage: &mut dyn Storage) -> StdResult<Bytes32> {
        let candidates_for_validator_set = get_signature_candidate_validators(storage)?;
        // self.validator_set = self.candidates_for_validator_set.to_owned();
        for candidate in &candidates_for_validator_set {
            validator_set().save(storage, &candidate.node_id, candidate)?;
        }

        // reset candidate for validator set
        reset_signature_candidate_validators(storage);

        self.total_weight = self.candidates_total_weight;
        self.sum_largest_total_weights = self.sum_largest_candidates_total_weights;

        self.candidates_total_weight = 0;
        self.sum_largest_candidates_total_weights = 0;
        let rh = self.root_hash;
        self.root_hash = Bytes32::default();

        Ok(rh)
    }

    fn set_validator_set(
        &mut self,
        storage: &mut dyn Storage,
        api: &dyn Api,
    ) -> StdResult<Bytes32> {
        let val_set = get_signature_validator_set(storage)?;
        // remove old validators from the list to prevent unexpected errors
        // reset_signature_validator_set(storage);
        let candidates_for_validator_set = get_signature_candidate_validators(storage)?;
        // if current validator_set is empty, check caller
        // else check votes
        if val_set[0].weight == 0 {
            return Err(StdError::generic_err("current validator_set is empty"));
        }

        let mut current_weight = 0;
        for validator in &val_set {
            if self.is_signed_by_validator(storage, validator.node_id, self.root_hash) {
                current_weight += validator.weight;
            }
        }

        api.debug(&format!(
            "current weight: {:?}, total weight: {:?}",
            current_weight * 3,
            self.sum_largest_total_weights * 2
        ));

        if current_weight * 3 <= self.sum_largest_total_weights * 2 {
            return Err(StdError::generic_err(format!(
                "not enough votes. Wanted {:?}; has {:?}",
                self.sum_largest_total_weights * 2,
                current_weight * 3
            )));
        }

        for candidate in &candidates_for_validator_set {
            validator_set().save(storage, &candidate.node_id, candidate)?;
        }
        reset_signature_candidate_validators(storage);

        self.total_weight = self.candidates_total_weight;
        self.sum_largest_total_weights = self.sum_largest_candidates_total_weights;

        self.candidates_total_weight = 0;
        self.sum_largest_candidates_total_weights = 0;
        let rh = self.root_hash;
        self.root_hash = EMPTY_HASH;
        self.has_next = self.has_candidate_next;
        self.has_candidate_next = false;

        Ok(rh)
    }

    fn parse_candidates_root_block(
        &mut self,
        storage: &mut dyn Storage,
        boc: &[u8],
    ) -> Result<(), ContractError> {
        // self.candidates_for_validator_set = ValidatorSet::default();
        self.candidates_total_weight = 0;
        let mut validators = self.get_validators_set_from_boc(boc)?;
        self.parse_validators(storage, &mut validators)?;

        Ok(())
    }

    fn get_validators_set_from_boc(
        &mut self,
        boc: &[u8],
    ) -> Result<KeyBlockValidators, ContractError> {
        // ref index = 3 because we skip load_block_info, load_value_flow, and load_merkle_update refs (dont care)
        let ref_index = &mut 3;
        let cells = BagOfCells::parse(boc)?;
        let first_root = cells.single_root()?;
        // set root hash as the hash of the first root
        self.root_hash = first_root.get_hash(0).as_slice().try_into()?;
        let mut parser = first_root.parser();

        // magic number
        parser.load_u32(32)?;
        // global id
        parser.load_i32(32)?;
        let block_extra = first_root
            .load_ref_if_exist(ref_index, Some(Cell::load_block_extra))?
            .0;
        if block_extra.is_none() {
            return Err(ContractError::TonCellError(
                TonCellError::cell_parser_error("Wrong boc for keyblock parsing"),
            ));
        }
        let block_extra = block_extra.unwrap();

        let mut key_block_vals = KeyBlockValidators::default();

        key_block_vals.current =
            SignatureValidator::load_validator_from_config_param(&block_extra.custom.config, 34)?;
        key_block_vals.previous =
            SignatureValidator::load_validator_from_config_param(&block_extra.custom.config, 32)
                .ok()
                .unwrap_or_default();
        key_block_vals.next =
            SignatureValidator::load_validator_from_config_param(&block_extra.custom.config, 36)
                .ok()
                .unwrap_or_default();

        Ok(key_block_vals)
    }

    fn load_validator_from_config_param(
        config_params: &ConfigParams,
        param_number: u8,
    ) -> Result<ValidatorSet, ContractError> {
        let config_param = config_params.config.get(&format!("{:02x}", param_number));
        if config_param.is_none() {
            return Err(ContractError::TonCellError(
                TonCellError::cell_parser_error("Validation infos not found"),
            ));
        }
        let config_param = config_param.unwrap();
        if config_param.is_none() {
            return Err(ContractError::TonCellError(
                TonCellError::cell_parser_error("Validation infos not found"),
            ));
        }
        let config_param = config_param.clone().unwrap();
        match config_param {
            ConfigParam::ConfigParams34(validator_infos) => {
                SignatureValidator::load_validator_set(validator_infos)
            }
            ConfigParam::ConfigParams36(validator_infos) => {
                SignatureValidator::load_validator_set(validator_infos)
            }
            ConfigParam::ConfigParams32(validator_infos) => {
                SignatureValidator::load_validator_set(validator_infos)
            }
        }
    }

    fn load_validator_set(
        validator_infos: ConfigParamsValidatorSet,
    ) -> Result<ValidatorSet, ContractError> {
        validator_infos
            .validators
            .list
            .iter()
            .map(|validator| {
                Ok(ValidatorDescription {
                    c_type: validator.1._type,
                    weight: validator.1.weight,
                    adnl_addr: validator.1.adnl_addr.as_slice().try_into()?,
                    pubkey: validator.1.public_key.as_slice().try_into()?,
                    node_id: Bytes32::default(),
                })
            })
            .collect::<Result<Vec<ValidatorDescription>, ContractError>>()
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::mock_dependencies, Api, HexBinary};

    const ED25519_MESSAGE_HEX: &str = "af82";
    const ED25519_SIGNATURE_HEX: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    const ED25519_PUBLIC_KEY_HEX: &str =
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

    #[test]
    fn test_signature_verify() {
        let deps = mock_dependencies();
        let message = HexBinary::from_hex(ED25519_MESSAGE_HEX).unwrap();
        let signature = HexBinary::from_hex(ED25519_SIGNATURE_HEX).unwrap();
        let public_key = HexBinary::from_hex(ED25519_PUBLIC_KEY_HEX).unwrap();
        let verfied = deps
            .api
            .ed25519_verify(&message, &signature, &public_key)
            .unwrap();

        println!("verified {}", verfied);
    }
}
