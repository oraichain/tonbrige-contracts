use cosmwasm_std::{Api, StdError, StdResult, Storage};
use cw_storage_plus::Map;
use tonbridge_parser::{
    bit_reader::{
        parse_dict, read_bit, read_bool, read_bytes32_bit_size, read_u16, read_u32, read_u64,
        read_u8,
    },
    block_parser::{BlockParser, IBlockParser, BLOCK_INFO_CELL},
    tree_of_cells_parser::EMPTY_HASH,
    types::{Bytes32, CachedCell, CellData, ValidatorDescription, Vdata, VerifiedBlockInfo},
};
use tonbridge_validator::shard_validator::MESSAGE_PREFIX;

use crate::state::SIGNED_BLOCKS;

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
        vdata: &[Vdata; 5],
    ) -> StdResult<()>;

    // fn parse_candidates_root_block(
    //     &self,
    //     boc: &[u8],
    //     root_idx: usize,
    //     tree_of_cells: &mut [CellData; 100],
    // ) -> StdResult<()>;

    // fn parse_part_validators(
    //     data: &[u8],
    //     cell_idx: usize,
    //     cells: &mut [CellData; 100],
    // ) -> StdResult<()>;

    fn is_signed_by_validator(
        &self,
        storage: &dyn Storage,
        node_id: Bytes32,
        root_h: Bytes32,
    ) -> bool;

    // fn init_validators(&self) -> StdResult<Bytes32>;
}

// need to deserialize from storage and better access directly from storage
#[derive(Default)]
pub struct SignatureValidator {
    pub validator_set: [ValidatorDescription; 20],
    total_weight: u64,
    pub pruned_cells: [CachedCell; 10],
    candidates_for_validator_set: [ValidatorDescription; 20],
    candidates_total_weight: u64,
    root_hash: Bytes32,
    block_parser: BlockParser,
}

impl SignatureValidator {
    pub fn new() -> Self {
        Self::default()
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
            return Err(StdError::generic_err("not enought votes"));
        }
        Ok(root_h)
    }

    fn verify_validators(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata; 5],
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
        for i in 0..5 {
            // 1. found validator
            for j in 0..self.validator_set.len() {
                if self.validator_set[j].node_id == vdata[i].node_id {
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
            if api.ed25519_verify(&message, &[0u8], &self.validator_set[validator_idx].pubkey)? {
                SIGNED_BLOCKS.save(
                    storage,
                    &[self.validator_set[validator_idx].node_id, test_root_hash].concat(),
                    &true,
                )?;
            }

            // if (Ed25519.verify(
            //     validator_set[validator_idx].pubkey,
            //     vdata[i].r,
            //     vdata[i].s,
            //     bytes.concat(bytes4(0x706e0bc5), test_root_hash, file_hash),
            // )) {
            //     signed_blocks[validator_set[validator_idx].node_id][test_root_hash] = true;
            // }
        }

        Ok(())
    }

    //     function init_validators() public onlyOwner returns (bytes32) {
    //         // require(validator_set[0].weight == 0, "current validators not empty");

    //         validator_set = candidates_for_validator_set;
    //         delete candidates_for_validator_set;

    //         total_weight = candidates_total_weight;
    //         candidates_total_weight = 0;
    //         bytes32 rh = root_hash;
    //         root_hash = 0;

    //         return (rh);
    //     }

    //     function set_validator_set() public returns (bytes32) {
    //         // if current validator_set is empty, check caller
    //         // else check votes
    //         require(validator_set[0].weight != 0);

    //         // check all pruned cells are empty
    //         for (uint256 i = 0; i < pruned_cells.length; i++) {
    //             require(pruned_cells[i].hash == 0, "need read all validators");
    //         }

    //         uint64 current_weight = 0;
    //         for (uint256 j = 0; j < validator_set.length; j++) {
    //             if (signed_blocks[validator_set[j].node_id][root_hash]) {
    //                 current_weight += validator_set[j].weight;
    //             }
    //         }

    //         require(current_weight * 3 > total_weight * 2, "not enought votes");

    //         validator_set = candidates_for_validator_set;
    //         delete candidates_for_validator_set;

    //         total_weight = candidates_total_weight;
    //         candidates_total_weight = 0;
    //         bytes32 rh = root_hash;
    //         root_hash = 0;

    //         return (rh);
    //     }

    //     function parse_candidates_root_block(
    //         bytes calldata boc,
    //         uint256 root_idx,
    //         CellData[100] memory tree_of_cells
    //     ) public {
    //         delete candidates_for_validator_set;
    //         candidates_total_weight = 0;
    //         delete pruned_cells;
    //         root_hash = tree_of_cells[root_idx]._hash[0];

    //         ValidatorDescription[32] memory validators = block_parser
    //             .parse_candidates_root_block(boc, root_idx, tree_of_cells);

    //         for (uint256 i = 0; i < 32; i++) {
    //             for (uint256 j = 0; j < 20; j++) {
    //                 // is empty
    //                 if (candidates_for_validator_set[j].weight == 0) {
    //                     candidates_total_weight += validators[i].weight;
    //                     candidates_for_validator_set[j] = validators[i];
    //                     candidates_for_validator_set[j].node_id = block_parser
    //                         .computeNodeId(candidates_for_validator_set[j].pubkey);
    //                     break;
    //                 }
    //                 // old validator has less weight then new
    //                 if (
    //                     candidates_for_validator_set[j].weight < validators[i].weight
    //                 ) {
    //                     candidates_total_weight += validators[i].weight;
    //                     candidates_total_weight -= candidates_for_validator_set[j]
    //                         .weight;

    //                     ValidatorDescription memory tmp = candidates_for_validator_set[
    //                         j
    //                     ];
    //                     candidates_for_validator_set[j] = validators[i];
    //                     validators[i] = tmp;

    //                     candidates_for_validator_set[j].node_id = block_parser
    //                         .computeNodeId(candidates_for_validator_set[j].pubkey);
    //                 }
    //             }
    //         }
    //     }

    //     function parse_part_validators(
    //         bytes calldata data,
    //         uint256 cell_idx,
    //         CellData[100] memory cells
    //     ) public {
    //         bool valid = false;
    //         uint256 prefixLength = 0;
    //         for (uint256 i = 0; i < 10; i++) {
    //             if (pruned_cells[i].hash == cells[cell_idx]._hash[0]) {
    //                 valid = true;
    //                 prefixLength = pruned_cells[i].prefixLength;
    //                 delete pruned_cells[i];
    //                 break;
    //             }
    //         }
    //         require(valid, "Wrong boc for validators");

    //         ValidatorDescription[32] memory validators = block_parser
    //             .parse_part_validators(data, cell_idx, cells, prefixLength);

    //         for (uint256 i = 0; i < 32; i++) {
    //             for (uint256 j = 0; j < 20; j++) {
    //                 // is empty
    //                 if (candidates_for_validator_set[j].weight == 0) {
    //                     candidates_total_weight += validators[i].weight;
    //                     candidates_for_validator_set[j] = validators[i];
    //                     candidates_for_validator_set[j].node_id = block_parser
    //                         .computeNodeId(candidates_for_validator_set[j].pubkey);
    //                     break;
    //                 }
    //                 // old validator has less weight then new
    //                 if (
    //                     candidates_for_validator_set[j].weight < validators[i].weight
    //                 ) {
    //                     candidates_total_weight += validators[i].weight;
    //                     candidates_total_weight -= candidates_for_validator_set[j]
    //                         .weight;

    //                     ValidatorDescription memory tmp = candidates_for_validator_set[
    //                         j
    //                     ];
    //                     candidates_for_validator_set[j] = validators[i];
    //                     validators[i] = tmp;

    //                     candidates_for_validator_set[j].node_id = block_parser
    //                         .computeNodeId(candidates_for_validator_set[j].pubkey);
    //                 }
    //             }
    //         }
    //     }
}
