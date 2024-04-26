use cosmwasm_std::{Addr, Api, DepsMut, StdError, StdResult, Storage};
use tonbridge_parser::{
    block_parser::ValidatorSet20,
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser, EMPTY_HASH},
    types::{Bytes32, CachedCell, Vdata, VerifiedBlockInfo},
};
use tonbridge_validator::shard_validator::{IShardValidator, ShardValidator};

use crate::{
    signature_validator::{ISignatureValidator, SignatureValidator},
    state::{OWNER, VERIFIED_BLOCKS},
};

pub trait IValidator {
    fn is_verified_block(&self, storage: &dyn Storage, root_hash: Bytes32) -> StdResult<bool>;
}

#[derive(Default)]
pub struct Validator {
    signature_validator: SignatureValidator,
    toc_parser: TreeOfCellsParser,
    shard_validator: ShardValidator,
}

impl Validator {
    pub fn is_signed_by_validator(
        &self,
        storage: &dyn Storage,
        node_id: Bytes32,
        root_h: Bytes32,
    ) -> bool {
        self.signature_validator
            .is_signed_by_validator(storage, node_id, root_h)
    }

    pub fn get_pruned_cells(&self) -> [CachedCell; 10] {
        self.signature_validator.pruned_cells
    }

    pub fn get_validators(&self) -> ValidatorSet20 {
        self.signature_validator.validator_set
    }

    pub fn get_candidates_for_validators(&self) -> ValidatorSet20 {
        self.signature_validator.candidates_for_validator_set
    }

    pub fn parse_candidates_root_block(&mut self, boc: &[u8]) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut tree_of_cells = self.toc_parser.get_tree_of_cells(boc, &mut header)?;
        self.signature_validator.parse_candidates_root_block(
            boc,
            header.root_idx,
            &mut tree_of_cells,
        )?;

        Ok(())
    }

    pub fn parse_part_validators(&mut self, boc: &[u8]) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut tree_of_cells = self.toc_parser.get_tree_of_cells(boc, &mut header)?;
        self.signature_validator
            .parse_part_validators(boc, header.root_idx, &mut tree_of_cells)?;

        Ok(())
    }

    pub fn init_validators(&mut self, deps: DepsMut, caller: &Addr) -> StdResult<()> {
        if !OWNER.is_admin(deps.as_ref(), caller)? {
            return Err(StdError::generic_err("unauthorized"));
        }
        let key_block_root_hash = self.signature_validator.init_validators()?;
        let mut verified_block_info = VerifiedBlockInfo::default();
        verified_block_info.verified = true;

        VERIFIED_BLOCKS.save(deps.storage, &key_block_root_hash, &verified_block_info)
    }

    pub fn set_validator_set(&mut self, storage: &mut dyn Storage) -> StdResult<()> {
        let key_block_root_hash = self.signature_validator.set_validator_set(storage)?;
        let mut verified_block_info = VerifiedBlockInfo::default();
        verified_block_info.verified = true;
        VERIFIED_BLOCKS.save(storage, &key_block_root_hash, &verified_block_info)
    }

    pub fn verify_validators(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        root_h: Bytes32,
        file_hash: Bytes32,
        vdata: &[Vdata; 5],
    ) -> StdResult<()> {
        self.signature_validator
            .verify_validators(storage, api, root_h, file_hash, vdata)
    }

    //     // fn setroot_hashForValidating(bytes32 rh) public {
    //     //     signature_validator.setroot_hashForValidating(rh);
    //     // }

    pub fn add_current_block_to_verified_set(
        &self,
        storage: &mut dyn Storage,
        root_h: Bytes32,
    ) -> StdResult<()> {
        let rh = self
            .signature_validator
            .add_current_block_to_verified_set(storage, root_h)?;
        let mut verified_block_info = VerifiedBlockInfo::default();
        verified_block_info.verified = true;
        VERIFIED_BLOCKS.save(storage, &rh, &verified_block_info)
    }

    pub fn parse_shard_proof_path(&self, storage: &mut dyn Storage, boc: &[u8]) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut toc = self.toc_parser.get_tree_of_cells(boc, &mut header)?;

        if !self.is_verified_block(storage, toc[toc[header.root_idx].refs[0]].hashes[0])? {
            return Err(StdError::generic_err("Not verified"));
        }

        let (root_hashes, blocks) =
            self.shard_validator
                .parse_shard_proof_path(boc, header.root_idx, &mut toc)?;

        for i in 0..root_hashes.len() {
            if root_hashes[i] == EMPTY_HASH {
                break;
            }

            VERIFIED_BLOCKS.save(storage, &root_hashes[i], &blocks[i])?;
        }

        Ok(())
    }

    pub fn add_prev_block(&self, storage: &mut dyn Storage, boc: &[u8]) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut toc = self.toc_parser.get_tree_of_cells(boc, &mut header)?;

        if !self.is_verified_block(storage, toc[toc[header.root_idx].refs[0]].hashes[0])? {
            return Err(StdError::generic_err("Not verified"));
        }

        let (root_hashes, blocks) =
            self.shard_validator
                .add_prev_block(boc, header.root_idx, &mut toc)?;

        for i in 0..root_hashes.len() {
            if root_hashes[i] == EMPTY_HASH {
                break;
            }

            VERIFIED_BLOCKS.save(storage, &root_hashes[i], &blocks[i])?;
        }

        Ok(())
    }

    pub fn read_master_proof(&self, storage: &mut dyn Storage, boc: &[u8]) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut toc = self.toc_parser.get_tree_of_cells(boc, &mut header)?;

        if !self.is_verified_block(storage, toc[header.root_idx].hashes[0])? {
            return Err(StdError::generic_err("Not verified"));
        }

        let new_hash = self
            .shard_validator
            .read_master_proof(boc, header.root_idx, &mut toc)?;

        let block_key = &toc[header.root_idx].hashes[0];
        let mut block = VERIFIED_BLOCKS.load(storage, block_key)?;
        block.new_hash = new_hash;

        VERIFIED_BLOCKS.save(storage, block_key, &block)
    }

    pub fn read_state_proof(
        &self,
        storage: &mut dyn Storage,
        boc: &[u8],
        rh: Bytes32,
    ) -> StdResult<()> {
        let mut header = self.toc_parser.parse_serialized_header(boc)?;
        let mut toc = self.toc_parser.get_tree_of_cells(boc, &mut header)?;

        let new_block = VERIFIED_BLOCKS.load(storage, &rh)?;

        if toc[header.root_idx].hashes[0] != new_block.new_hash {
            return Err(StdError::generic_err("Block with new hash is not verified"));
        }

        let (root_hashes, blocks) =
            self.shard_validator
                .read_state_proof(boc, header.root_idx, &mut toc)?;

        for i in 0..root_hashes.len() {
            if root_hashes[i] == EMPTY_HASH {
                break;
            }

            VERIFIED_BLOCKS.save(storage, &root_hashes[i], &blocks[i])?;
        }

        Ok(())
    }

    pub fn set_verified_block(
        &self,
        deps_mut: DepsMut,
        caller: &Addr,
        root_hash: Bytes32,
        seq_no: u32,
    ) -> StdResult<()> {
        let deps = deps_mut.as_ref();
        if !OWNER.is_admin(deps, caller)? {
            return Err(StdError::generic_err("unauthorized"));
        }
        if self.is_verified_block(deps.storage, root_hash)? {
            return Err(StdError::generic_err("block already verified"));
        }

        let mut block = VerifiedBlockInfo::default();
        block.verified = true;
        block.seq_no = seq_no;

        VERIFIED_BLOCKS.save(deps_mut.storage, &root_hash, &block)
    }
}

impl IValidator for Validator {
    fn is_verified_block(&self, storage: &dyn Storage, root_hash: Bytes32) -> StdResult<bool> {
        Ok(VERIFIED_BLOCKS.load(storage, &root_hash)?.verified)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;
    use tonbridge_parser::tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser};

    const MASTER_PROOF :&str = "b5ee9c72c102070100011500000e0034005a00a300c900ef0115241011ef55aafffffffd010203062848010157d5d40d6835fb10eab860add2c9ed9384007cbd5c4af7006716f5eeb6109092000128480101c3b6883898411dde154d6b1040de039f6adcb180ce452ba14459b202a7be8bd600030a8a045525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e36184f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f001f0405284801015525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e3618001f284801014f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f284801011ca3e8075b0f29141deae260b25832844ffdaea9e42d41e9c62f0bf875a132d800075572e271";

    #[test]
    fn test_master_proof() {
        let tree_of_cells_parser = TreeOfCellsParser::default();
        let boc = HexBinary::from_hex(MASTER_PROOF).unwrap().to_vec();

        let mut header = tree_of_cells_parser.parse_serialized_header(&boc).unwrap();

        let toc = tree_of_cells_parser
            .get_tree_of_cells(&boc, &mut header)
            .unwrap();

        println!("{}", header.root_idx);
        println!("{}", toc[0].special)
    }
}
