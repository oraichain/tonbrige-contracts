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

        for mut total_validator in total_validators {
            // if the candidate is already in the list, we compare weight with the input
            if let Some(candidate) = candidates_for_validator_set.iter_mut().find(|val| {
                HexBinary::from(val.pubkey)
                    .to_hex()
                    .eq(&HexBinary::from(total_validator.pubkey).to_string())
            }) {
                // old validator has less weight then new
                if candidate.weight < total_validator.weight {
                    self.candidates_total_weight += total_validator.weight;
                    self.candidates_total_weight -= candidate.weight;

                    std::mem::swap(candidate, &mut total_validator);

                    candidate.node_id = compute_node_id(candidate.pubkey);
                }
            }
            // not found, we push a new default validator and update its info
            candidates_for_validator_set.push(ValidatorDescription::default());

            self.candidates_total_weight += total_validator.weight;
            candidates_for_validator_set[j] = total_validator;
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
        if val_set.len() == 0 {
            return Err(StdError::generic_err("current validator_set is empty"));
        }
        if val_set[0].weight == 0 {
            return Err(StdError::generic_err(
                "current validator_set has zero weight",
            ));
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
    use cosmwasm_std::{testing::mock_dependencies, Api, HexBinary, StdError};
    use tonbridge_parser::{
        to_bytes32,
        types::{Bytes32, KeyBlockValidators, ValidatorDescription, Vdata},
        EMPTY_HASH,
    };

    use crate::state::{validator_set, SIGNATURE_CANDIDATE_VALIDATOR, SIGNED_BLOCKS};

    use super::{ISignatureValidator, SignatureValidator};

    const ED25519_MESSAGE_HEX: &str = "af82";
    const ED25519_SIGNATURE_HEX: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    const ED25519_PUBLIC_KEY_HEX: &str =
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

    fn convert_byte32(str: &str) -> Bytes32 {
        HexBinary::from_hex(str)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap()
    }

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

    #[test]
    fn test_parse_validators() {
        let mut deps = mock_dependencies();
        let mut validators: KeyBlockValidators = KeyBlockValidators::default();
        validators.current = vec![
            ValidatorDescription {
                c_type: 1,
                weight: 3,
                adnl_addr: EMPTY_HASH,
                pubkey: to_bytes32(
                    &HexBinary::from_hex(
                        "3827e3ec4a5b93141efb9ced816d13248bf1fa1506f03b5a69e109657682e12c",
                    )
                    .unwrap(),
                )
                .unwrap(),
                node_id: to_bytes32(
                    &HexBinary::from_hex(
                        "3827e3ec4a5b93141efb9ced816d13248bf1fa1506f03b5a69e109657682e12c",
                    )
                    .unwrap(),
                )
                .unwrap(),
            },
            ValidatorDescription {
                c_type: 1,
                weight: 1,
                adnl_addr: EMPTY_HASH,
                pubkey: to_bytes32(
                    &HexBinary::from_hex(
                        "8e803f1f6dfed804d600be94330482a827921f18a8074e5a36bc9e977b9b2f5d",
                    )
                    .unwrap(),
                )
                .unwrap(),
                node_id: to_bytes32(
                    &HexBinary::from_hex(
                        "8e803f1f6dfed804d600be94330482a827921f18a8074e5a36bc9e977b9b2f5d",
                    )
                    .unwrap(),
                )
                .unwrap(),
            },
        ];
        let mut sig_val = SignatureValidator::default();

        SIGNATURE_CANDIDATE_VALIDATOR
            .save(
                deps.as_mut().storage,
                0,
                &ValidatorDescription {
                    c_type: 1,
                    weight: 2,
                    adnl_addr: EMPTY_HASH,
                    pubkey: to_bytes32(
                        &HexBinary::from_hex(
                            "3827e3ec4a5b93141efb9ced816d13248bf1fa1506f03b5a69e109657682e12c",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    node_id: to_bytes32(
                        &HexBinary::from_hex(
                            "3827e3ec4a5b93141efb9ced816d13248bf1fa1506f03b5a69e109657682e12c",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                },
            )
            .unwrap();

        sig_val
            .parse_validators(deps.as_mut().storage, &mut validators)
            .unwrap();

        assert_eq!(sig_val.candidates_total_weight, 4u64);
        assert_eq!(sig_val.has_candidate_next, false);
        assert_eq!(sig_val.has_next, false);
        assert_eq!(sig_val.root_hash, EMPTY_HASH);
        assert_eq!(sig_val.sum_largest_candidates_total_weights, 4);
        assert_eq!(sig_val.sum_largest_total_weights, 0);
    }

    #[test]
    fn test_is_signed_by_validator() {
        let mut deps = mock_dependencies();
        let sig_val = SignatureValidator::default();
        let is_signed =
            sig_val.is_signed_by_validator(deps.as_mut().storage, EMPTY_HASH, EMPTY_HASH);

        assert_eq!(is_signed, false);

        SIGNED_BLOCKS
            .save(
                deps.as_mut().storage,
                &[EMPTY_HASH, EMPTY_HASH].concat(),
                &true,
            )
            .unwrap();

        let is_signed =
            sig_val.is_signed_by_validator(deps.as_mut().storage, EMPTY_HASH, EMPTY_HASH);
        assert_eq!(is_signed, true);
    }

    #[test]
    fn test_init_validators() {
        let mut deps = mock_dependencies();
        let mut sig_val = SignatureValidator::default();
        let root_hash =
            HexBinary::from_hex("5d5215c4dd5e2dc3e8b0640339303135cd7296c577e37d1f0e1781cde6fb9629")
                .unwrap();
        let total_weight = 2;
        let first_candidate_pubkey =
            convert_byte32("3827e3ec4a5b93141efb9ced816d13248bf1fa1506f03b5a69e109657682e12c");

        SIGNATURE_CANDIDATE_VALIDATOR
            .save(
                deps.as_mut().storage,
                0,
                &ValidatorDescription {
                    c_type: 1,
                    weight: total_weight,
                    adnl_addr: EMPTY_HASH,
                    pubkey: first_candidate_pubkey,
                    node_id: first_candidate_pubkey,
                },
            )
            .unwrap();

        sig_val.root_hash = to_bytes32(&root_hash).unwrap();
        sig_val.candidates_total_weight = total_weight;
        sig_val.sum_largest_candidates_total_weights = total_weight;
        let rh = sig_val.init_validators(deps.as_mut().storage).unwrap();

        assert_eq!(rh, to_bytes32(&root_hash).unwrap());
        assert_eq!(sig_val.root_hash, EMPTY_HASH);
        assert_eq!(sig_val.candidates_total_weight, 0);
        assert_eq!(sig_val.has_candidate_next, false);
        assert_eq!(sig_val.has_next, false);
        assert_eq!(sig_val.total_weight, total_weight);
        assert_eq!(sig_val.sum_largest_total_weights, total_weight);
        assert_eq!(sig_val.sum_largest_candidates_total_weights, 0);

        assert_eq!(
            validator_set()
                .load(deps.as_mut().storage, &first_candidate_pubkey)
                .unwrap()
                .pubkey,
            first_candidate_pubkey
        );
    }

    #[test]
    fn test_verify_signature() {
        // TODO: use the signatures that we have pubkeys that match.
        let signatures = [
            Vdata {
                node_id: convert_byte32(
                    "80de0302ef8970b077e702b227a1bae646530b6b3630d1dd0d81541971757ff3",
                ),
                r: convert_byte32(
                    "5efa07dac65c347fa70fde65312a0a0a8a1f76aae9adbec6058a80e7f5202e5e",
                ),
                s: convert_byte32(
                    "3946227c0d480cb4794bc7d6a5c4d5d0c2d80b08bb937b063b6eecb7ec9e7a08",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "4ff320aca951fac7e49be0c5d375e21a88be531193dfab791a9fed2ebeea4eb2",
                ),
                r: convert_byte32(
                    "e623088e43a0151925583e2a3b861e9270cab4cc223a2e01b856f123e6d0dbc9",
                ),
                s: convert_byte32(
                    "341bacfc1bfbc28aadaf914cf93c9bf43f2e4f7bccdebbf3e62c98f82d697004",
                ),
            },
        ];

        let root_hash =
            convert_byte32("292edb12dadb1b56db5c44687bf1311dcac38089f8b895b11bf0c8fbd605989e");
        let file_hash =
            convert_byte32("dfd3c0f265e62f340cb8020a0a3b5d0503d71ca84d5f40b2372e858147c03ba1");

        let mut deps = mock_dependencies();
        let mut validator = SignatureValidator::default();

        // case 1: current weight should be 0 since there's no validator set stored yet matching these signatures
        let current_weight = validator
            .verify_validators(
                &mut deps.storage,
                &deps.api,
                root_hash,
                file_hash,
                &signatures,
            )
            .unwrap();
        assert_eq!(current_weight, 0);

        // case 2: when a block is re-checked, we also verify using validators and increment the weight
        SIGNED_BLOCKS
            .save(
                deps.as_mut().storage,
                &[signatures[0].node_id, root_hash].concat(),
                &true,
            )
            .unwrap();

        let mut first_val = ValidatorDescription::default();
        first_val.weight = 2;
        first_val.node_id = signatures[0].node_id;
        validator_set()
            .save(deps.as_mut().storage, &signatures[0].node_id, &first_val)
            .unwrap();

        let current_weight = validator
            .verify_validators(
                &mut deps.storage,
                &deps.api,
                root_hash,
                file_hash,
                &signatures,
            )
            .unwrap();
        assert_eq!(current_weight, 2);
    }

    #[test]
    fn test_set_validator_set() {
        let mut deps = mock_dependencies();
        let mut sig_val = SignatureValidator::default();
        let deps_mut = deps.as_mut();

        // case 1: empty valset
        let err = sig_val
            .set_validator_set(deps_mut.storage, deps_mut.api)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            StdError::generic_err("current validator_set is empty").to_string()
        );

        // case 2: empty weight
        let mut first_val = ValidatorDescription::default();
        first_val.weight = 0;
        first_val.node_id =
            convert_byte32("80de0302ef8970b077e702b227a1bae646530b6b3630d1dd0d81541971757ff3");
        validator_set()
            .save(deps_mut.storage, &first_val.node_id, &first_val)
            .unwrap();

        let err = sig_val
            .set_validator_set(deps_mut.storage, deps_mut.api)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            StdError::generic_err("current validator_set has zero weight").to_string()
        );

        // case 3, not enough votes
        first_val.weight = 3;
        validator_set()
            .save(deps_mut.storage, &first_val.node_id, &first_val)
            .unwrap();
        sig_val.sum_largest_total_weights = 3;
        let err = sig_val
            .set_validator_set(deps_mut.storage, deps_mut.api)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            StdError::generic_err(&format!(
                "not enough votes. Wanted {:?}; has {:?}",
                sig_val.sum_largest_total_weights * 2,
                0,
            ))
            .to_string()
        );

        // case 4: happy case
        let root_hash =
            convert_byte32("292edb12dadb1b56db5c44687bf1311dcac38089f8b895b11bf0c8fbd605989e");
        let total_weight = 4;
        SIGNED_BLOCKS
            .save(
                deps_mut.storage,
                &[first_val.node_id, root_hash].concat(),
                &true,
            )
            .unwrap();

        SIGNATURE_CANDIDATE_VALIDATOR
            .save(deps_mut.storage, 0, &first_val)
            .unwrap();

        sig_val.root_hash = root_hash;
        sig_val.candidates_total_weight = total_weight;
        sig_val.sum_largest_candidates_total_weights = total_weight;
        let rh = sig_val
            .set_validator_set(deps_mut.storage, deps_mut.api)
            .unwrap();
        assert_eq!(rh, root_hash);
        assert_eq!(sig_val.root_hash, EMPTY_HASH);
        assert_eq!(sig_val.total_weight, total_weight);
        assert_eq!(sig_val.sum_largest_total_weights, total_weight);
        assert_eq!(sig_val.candidates_total_weight, 0);
        assert_eq!(sig_val.sum_largest_candidates_total_weights, 0);

        assert_eq!(
            validator_set()
                .load(deps.as_mut().storage, &first_val.node_id)
                .unwrap()
                .pubkey,
            first_val.pubkey
        );
    }
}
