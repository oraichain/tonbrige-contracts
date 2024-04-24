use cosmwasm_std::{StdError, StdResult};
use cw_storage_plus::Map;
use tonbridge_parser::{
    bit_reader::{
        parse_dict, read_bit, read_bool, read_bytes32_bit_size, read_u16, read_u32, read_u64,
        read_u8,
    },
    block_parser::{BlockParser, IBlockParser, BLOCK_INFO_CELL},
    types::{Bytes32, CachedCell, CellData, ValidatorDescription, Vdata, VerifiedBlockInfo},
};

pub trait ISignatureValidator {
    fn get_pruned_cells(&self) -> StdResult<[CachedCell; 10]>;

    fn add_current_block_to_verified_set(&self, root_h: Bytes32) -> StdResult<Bytes32>;

    // fn setRootHashForValidating(bytes32 rh) external;

    fn verify_validators(
        &self,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata; 5],
    ) -> StdResult<()>;

    fn get_validators(&self) -> StdResult<[ValidatorDescription; 20]>;

    fn get_candidates_for_validators(&self) -> StdResult<[ValidatorDescription; 20]>;

    fn set_validator_set(&self) -> StdResult<Bytes32>;

    fn parse_candidates_root_block(
        &self,
        boc: &[u8],
        root_idx: usize,
        tree_of_cells: &mut [CellData; 100],
    ) -> StdResult<()>;

    fn parse_part_validators(
        data: &[u8],
        cell_idx: usize,
        cells: &mut [CellData; 100],
    ) -> StdResult<()>;

    fn is_signed_by_validator(&self, node_id: Bytes32, root_h: Bytes32) -> StdResult<bool>;

    fn init_validators(&self) -> StdResult<Bytes32>;
}

// need to deserialize from storage and better access directly from storage
#[derive(Default)]
pub struct SignatureValidator {
    validator_set: [ValidatorDescription; 20],
    total_weight: u64,
    pruned_cells: [CachedCell; 10],
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
    //     constructor(address block_parserAddr) {
    //         block_parser = IBlockParser(block_parserAddr);
    //     }

    //     function is_signed_by_validator(
    //         bytes32 node_id,
    //         bytes32 root_h
    //     ) public view returns (bool) {
    //         return signed_blocks[node_id][root_h];
    //     }

    //     function get_pruned_cells() public view returns (CachedCell[10] memory) {
    //         return pruned_cells;
    //     }

    //     function get_validators()
    //         public
    //         view
    //         returns (ValidatorDescription[20] memory)
    //     {
    //         return validator_set;
    //     }

    //     function get_candidates_for_validators()
    //         public
    //         view
    //         returns (ValidatorDescription[20] memory)
    //     {
    //         return candidates_for_validator_set;
    //     }

    //     // function setRootHashForValidating(bytes32 rh) public {
    //     //     root_hash = rh;
    //     // }

    //     function add_current_block_to_verified_set(
    //         bytes32 root_h
    //     ) public view returns (bytes32) {
    //         uint64 currentWeight = 0;
    //         for (uint256 j = 0; j < validator_set.length; j++) {
    //             if (signed_blocks[validator_set[j].node_id][root_h]) {
    //                 currentWeight += validator_set[j].weight;
    //             }
    //         }

    //         require(currentWeight * 3 > total_weight * 2, "not enought votes");

    //         return root_h;
    //     }

    //     function verify_validators(
    //         bytes32 root_h,
    //         bytes32 file_hash,
    //         Vdata[5] calldata vdata
    //     ) public {
    //         bytes32 test_root_hash = root_hash == 0 ? root_h : root_hash;

    //         require(
    //             test_root_hash != 0 && file_hash != 0,
    //             "wrong root_hash or file_hash"
    //         );

    //         uint256 validatodIdx = validator_set.length;
    //         for (uint256 i = 0; i < 5; i++) {
    //             // 1. found validator
    //             for (uint256 j = 0; j < validator_set.length; j++) {
    //                 if (validator_set[j].node_id == vdata[i].node_id) {
    //                     validatodIdx = j;
    //                     break;
    //                 }
    //             }
    //             // skip others node_ids and already checked node_ids
    //             if (
    //                 validatodIdx == validator_set.length ||
    //                 (signed_blocks[validator_set[validatodIdx].node_id][
    //                     test_root_hash
    //                 ] == true)
    //             ) {
    //                 continue;
    //             }
    //             // require(validatodIdx != validator_set.length, "wrong node_id");
    //             if (
    //                 Ed25519.verify(
    //                     validator_set[validatodIdx].pubkey,
    //                     vdata[i].r,
    //                     vdata[i].s,
    //                     bytes.concat(bytes4(0x706e0bc5), test_root_hash, file_hash)
    //                 )
    //             ) {
    //                 signed_blocks[validator_set[validatodIdx].node_id][
    //                     test_root_hash
    //                 ] = true;
    //             }
    //         }
    //     }

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

    //         uint64 currentWeight = 0;
    //         for (uint256 j = 0; j < validator_set.length; j++) {
    //             if (signed_blocks[validator_set[j].node_id][root_hash]) {
    //                 currentWeight += validator_set[j].weight;
    //             }
    //         }

    //         require(currentWeight * 3 > total_weight * 2, "not enought votes");

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
