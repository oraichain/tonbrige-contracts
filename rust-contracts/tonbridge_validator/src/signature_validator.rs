use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Api, HexBinary, StdError, StdResult, Storage};
use tonbridge_parser::{
    block_parser::{compute_node_id, BlockParser, IBlockParser, ValidatorSet, ValidatorSet32},
    tree_of_cells_parser::EMPTY_HASH,
    types::{Bytes32, CachedCell, CellData, ValidatorDescription, Vdata},
};
use tonbridge_validator::shard_validator::MESSAGE_PREFIX;
use tonlib::cell::{BagOfCells, Cell};

use crate::{state::SIGNED_BLOCKS, validator};

pub trait ISignatureValidator {
    fn add_current_block_to_verified_set(
        &self,
        storage: &dyn Storage,
        root_h: Bytes32,
    ) -> StdResult<Bytes32>;

    fn verify_validators(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata],
    ) -> StdResult<()>;

    fn parse_candidates_root_block(
        &mut self,
        boc: &[u8],
        root_idx: usize,
        tree_of_cells: &mut [CellData],
    ) -> StdResult<()>;

    fn parse_part_validators(
        &mut self,
        data: &[u8],
        cell_idx: usize,
        cells: &mut [CellData],
    ) -> StdResult<()>;

    fn is_signed_by_validator(
        &self,
        storage: &dyn Storage,
        node_id: Bytes32,
        root_h: Bytes32,
    ) -> bool;

    fn set_validator_set(&mut self, storage: &dyn Storage) -> StdResult<Bytes32>;

    fn init_validators(&mut self) -> StdResult<Bytes32>;

    fn get_validators_set_from_boc(&mut self, boc: &[u8]) -> StdResult<ValidatorSet>;
}

// need to deserialize from storage and better access directly from storage
#[cw_serde]
#[derive(Default)]
pub struct SignatureValidator {
    pub validator_set: ValidatorSet,
    total_weight: u64,
    pub pruned_cells: [CachedCell; 10],
    pub candidates_for_validator_set: ValidatorSet,
    candidates_total_weight: u64,
    root_hash: Bytes32,
    block_parser: BlockParser,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self::default()
    }
    fn parse_validators(&mut self, validators: &mut ValidatorSet) {
        let mut j = self.candidates_for_validator_set.len();
        for i in 0..validators.len() {
            // if the candidate is already in the list, we compare weight with the input
            if let Some(candidate) = self.candidates_for_validator_set.iter_mut().find(|val| {
                HexBinary::from(val.pubkey)
                    .to_hex()
                    .eq(&HexBinary::from(&validators[i].pubkey).to_string())
            }) {
                // old validator has less weight then new
                if candidate.weight < validators[i].weight {
                    self.candidates_total_weight += validators[i].weight;
                    self.candidates_total_weight -= candidate.weight;

                    std::mem::swap(candidate, &mut validators[i]);

                    candidate.node_id = compute_node_id(candidate.pubkey);
                }
            }
            // not found, we push a new default validator and update its info
            self.candidates_for_validator_set
                .push(ValidatorDescription::default());
            self.candidates_total_weight += validators[i].weight;
            self.candidates_for_validator_set[j] = validators[i];
            self.candidates_for_validator_set[j].node_id =
                compute_node_id(self.candidates_for_validator_set[j].pubkey);
            // increment size of validator set
            j += 1;
        }
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
    ) -> StdResult<Bytes32> {
        let mut current_weight = 0;
        for j in 0..self.validator_set.len() {
            if self.is_signed_by_validator(storage, self.validator_set[j].node_id, root_h) {
                current_weight += self.validator_set[j].weight;
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
    ) -> StdResult<()> {
        let test_root_hash = if self.root_hash == EMPTY_HASH {
            root_h
        } else {
            self.root_hash
        };

        if test_root_hash == EMPTY_HASH || file_hash == EMPTY_HASH {
            return Err(StdError::generic_err("wrong root_hash or file_hash"));
        }

        let mut validator_idx = self.validator_set.len();
        for vdata_item in vdata {
            // 1. found validator
            for j in 0..self.validator_set.len() {
                if self.validator_set[j].node_id == vdata_item.node_id {
                    validator_idx = j;
                    break;
                }
            }
            // skip others node_ids and already checked node_ids
            if validator_idx == self.validator_set.len()
                || self.is_signed_by_validator(
                    storage,
                    self.validator_set[validator_idx].node_id,
                    test_root_hash,
                )
            {
                continue;
            }
            // require(validator_idx != validator_set.length, "wrong node_id");
            let mut message = MESSAGE_PREFIX.to_vec();
            message.extend_from_slice(&test_root_hash);
            message.extend_from_slice(&file_hash);

            // signature = r + s
            if api.ed25519_verify(
                &message,
                &[vdata_item.r, vdata_item.s].concat(),
                &self.validator_set[validator_idx].pubkey,
            )? {
                // update as verified
                SIGNED_BLOCKS.save(
                    storage,
                    &[self.validator_set[validator_idx].node_id, test_root_hash].concat(),
                    &true,
                )?;
            }
        }

        Ok(())
    }

    fn init_validators(&mut self) -> StdResult<Bytes32> {
        // TODO: using Item storage
        self.validator_set = self.candidates_for_validator_set.to_owned();
        self.candidates_for_validator_set = ValidatorSet::default();

        self.total_weight = self.candidates_total_weight;
        self.candidates_total_weight = 0;
        let rh = self.root_hash;
        self.root_hash = Bytes32::default();

        Ok(rh)
    }

    fn set_validator_set(&mut self, storage: &dyn Storage) -> StdResult<Bytes32> {
        // if current validator_set is empty, check caller
        // else check votes
        if self.validator_set[0].weight == 0 {
            return Err(StdError::generic_err("current validator_set is empty"));
        }

        // check all pruned cells are empty
        for pruned_cell in &self.pruned_cells {
            if pruned_cell.hash != EMPTY_HASH {
                return Err(StdError::generic_err("need read all validators"));
            }
        }

        let mut current_weight = 0;
        for validator in &self.validator_set {
            if self.is_signed_by_validator(storage, validator.node_id, self.root_hash) {
                current_weight += validator.weight;
            }
        }

        if current_weight * 3 <= self.total_weight * 2 {
            return Err(StdError::generic_err("not enough votes"));
        }

        self.validator_set = self.candidates_for_validator_set.to_owned();
        self.candidates_for_validator_set = ValidatorSet::default();

        self.total_weight = self.candidates_total_weight;
        self.candidates_total_weight = 0;
        let rh = self.root_hash;
        self.root_hash = EMPTY_HASH;

        Ok(rh)
    }

    fn parse_candidates_root_block(
        &mut self,
        boc: &[u8],
        root_idx: usize,
        tree_of_cells: &mut [CellData],
    ) -> StdResult<()> {
        self.candidates_for_validator_set = ValidatorSet::default();
        self.candidates_total_weight = 0;
        self.pruned_cells = [CachedCell::default(); 10];
        self.root_hash = tree_of_cells[root_idx].hashes[0];

        // let mut validators =
        //     self.block_parser
        //         .parse_candidates_root_block(boc, root_idx, tree_of_cells)?;

        let validators = self.get_validators_set_from_boc(boc)?;

        self.parse_validators(&mut validators.to_vec());

        Ok(())
    }

    fn get_validators_set_from_boc(&mut self, boc: &[u8]) -> StdResult<ValidatorSet> {
        let ref_index = &mut 3;
        let cells = BagOfCells::parse(boc).unwrap();
        let first_root = cells.single_root().unwrap();
        let mut parser = first_root.parser();

        // magic number
        parser.load_u32(32).unwrap();
        // global id
        parser.load_i32(32).unwrap();

        let block_extra = first_root
            .load_ref_if_exist(ref_index, Some(Cell::load_block_extra))
            .unwrap()
            .0
            .unwrap();
        let validator_infos = block_extra
            .custom
            .config
            .config
            .get("22")
            .unwrap()
            .clone()
            .unwrap()
            .cur_validators;

        let mut validators: Vec<ValidatorDescription> =
            vec![ValidatorDescription::default(); validator_infos.list.len()];

        for (key, validator) in validator_infos.list.iter() {
            let index = usize::from_str_radix(key, 16).unwrap();
            validators[index] = ValidatorDescription {
                c_type: 0x73,
                weight: validator.weight,
                adnl_addr: validator.adnl_addr.as_slice().try_into().unwrap(),
                pubkey: validator.public_key.as_slice().try_into().unwrap(),
                node_id: Bytes32::default(),
            };
        }

        Ok(validators)
    }

    fn parse_part_validators(
        &mut self,
        data: &[u8],
        cell_idx: usize,
        cells: &mut [CellData],
    ) -> StdResult<()> {
        let mut valid = false;
        let mut prefix_length = 0;
        for i in 0..self.pruned_cells.len() {
            if self.pruned_cells[i].hash == cells[cell_idx].hashes[0] {
                valid = true;
                prefix_length = self.pruned_cells[i].prefix_length;
                self.pruned_cells[i] = CachedCell::default();
                break;
            }
        }
        if !valid {
            return Err(StdError::generic_err("Wrong boc for validators"));
        }

        let mut validators =
            self.block_parser
                .parse_part_validators(data, cell_idx, cells, prefix_length)?;

        self.parse_validators(&mut validators.to_vec());

        Ok(())
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
