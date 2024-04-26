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

    use super::Validator;

    const MASTER_PROOF :&str = "b5ee9c72c102070100011500000e0034005a00a300c900ef0115241011ef55aafffffffd010203062848010157d5d40d6835fb10eab860add2c9ed9384007cbd5c4af7006716f5eeb6109092000128480101c3b6883898411dde154d6b1040de039f6adcb180ce452ba14459b202a7be8bd600030a8a045525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e36184f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f001f0405284801015525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e3618001f284801014f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f284801011ca3e8075b0f29141deae260b25832844ffdaea9e42d41e9c62f0bf875a132d800075572e271";
    const BOCS:&str = "b5ee9c72410234010007c900041011ef55aafffffffd0103040501a09bc7a987000000000601004262100000000000ffffffff000000000000000063566c62000004d23f800dc0000004d23f800dc708fd4f290000df980042620d00425a75c400000003000000000000002e0208480101622689df2205931afa1d7c115f79f8fac4ea73f4edb05fabdca81c020f22a6130000084801012dfc806d1c50694678c34d5816e9316a00b94b05e085b5f97db07e9d8883040a0003084801011a6a28d6cea96f567bc6cd7da3ef88328865235ddd97386477d1436ce553595a001a04894a33f6fd5efff688d3a3cb98a24a4a498c8a67fd66e28a75139bf8363cd39ba56ebafdbedc9fcfce7dd2bf882a6833fb941d6e10bdc82bd9b2a4d123d114b81dde215c54c00607080908480101d72c3cbab4c1aded3d3342b743ec8f1f87d3d2656c439d39eccd5bab779c48e2000c08480101145ebae9f5d86e55979e5b6fcc1be5e39d70001e487d40a0bc4773b802c0fe4b000c08480101aef4bc8f76ad0dfb68e5a5c151d0fb544f45483ed32cacafde88ddb50a1121da000e0457cca5e87735940043b9aca002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac0a0b0c0d08480101501d1b77377edb7e682530a6ea1678615080b4bd76d9b1591b6c921688b02a12000208480101e18e1a1a40f3e0ccfcc3fc904f6ae42006e9e1c78ce6ef4bbffbf7d6e3770895000008480101f510fd883f3bd56c0f3e7cb3ab4684b225b34998cbea82a9a3e446d2dde602a300040201200e330202d80f320201201011084801018a67f6328db6b01c422c97114927cd9f39ca6e9578d437debecdf1091a4e98d7000d020162123102012013140848010162c1ea84ef6c2221181abacda0baff83ac88e6d3dd77f16ce981319739dcdf70000601014815012b12635650f663566d16000e000e0ffffffffffffff8c0160202cc1726020120181f020120191c0201201a1b009b1ce3a049e2a2518bdda34c61d6688c3dcbbe4af6f340a8271e475039a80694fd090278922840492492492492493b0391252e60a1cf81bbacde546f1e2805087fc291d5da465d963bc14e53df9060009b1ce3a049e2aaeb6babda7e323ceb3052c9361f70c7c7e12ed7e64f1935df83ca21d0c30ca4c0492492492492491d24bbd188fe0ffa6fe5affaed46c3913b84d00011c04c9bf6e3a576387144c2e00201201d1e009b1ce3a049e2a7fa088020c2a7fdfa4a91c0aac7a69c3826ff06394142059cf5893fa442bbd800492492492492492d2eaf1e23aac0ed093523bcd157e2fc7bc76ec0f3777a0772a25a9d493f9338a0009b1ce3a049e28e87ef1aac2280bf5fbf1869d0bb94ac94c9a7f2922b757b41968231a7d0bff70049249249249249154e4c591dc8671e0169285fbf6dbf498a767668892de738e800cdc902660378e002012020230201202122009b1ce3a049e2b714cbc17f2056cc2123f17ad04ce3a8e19da0627da7f27ac6246038fe66ee3e404924924924924903e69b47ddd935888b818916e6ef5be4323655182b6c93dd8ab5f902b2f12584e0009b1ce3a049e29d989ee1e95c5fa72aacea0112a3dd7f636a62d44b015f95b7bfaa454a7e6d5cc04924924924924919f259fff0b013a108033f9f5e92a0f76940f8841876ff02b0f7142c2c79bdbc200201202425009b1ce3a049e2b727f3f39f74afe20a9a0cfee5075b842f720af66ca93448f4452e0777885715004924924924924917b92409e2a3f8307539cefb50b14617198615bbe5de202fefe644c72588260460009b1ce3a049e29d21582596bfcc6d1de358003ef042e5207f4c804d7a1c7eb4df45e61dcb12bac0492492492492492632154ae74d72cbf208021b88ec8d3d89a3fcc246e6532354b918b784c81030a0020120272e020120282b020120292a009b1ce3a049e2bb5203d6b26731acaa20369ddcf706ef8a861473e9c00fe2051695440e366cb9804924924924924924d365a568e1356f3d7e3b9949501619745721ca7cf0feb0fad4d2f8847c283020009b1ce3a049e2b5e9e4f9e2be0699846cd5462dd33c0db38ed1e20a8e2b5a11ea6d6fd71eb35b80492492492492493d7579a885d03932c5eba75600dceb15b9b2ae4968d27b4b80c640d6bfe60615a00201202c2d009b1ce3a049e2a25935e71c9cf1b50eadc3bb29e330df9cea0d3b68cd6aff8eedc2659ccab428404924924924924902cdb4413b9ee19a9b2db5e70ac0e41126747c2fee2edd6f2a224f09cf8d6be1e0009b1ce3a049e2b0b092e100a69d80c496cbb06414bc2512888a9c398315ad596b57764098164cc0492492492492491a0b69ee5777de48e854d7d2af8d143b0e0ab1930204b4f9e3a0ec57c2722f57e00201482f30009b1ce3a049e280d5bc09be3be73173d7e7cf402cc5706e9b4f1e5328331252638d4b6e187161004924924924924910d373d1795c02c745f16012330554d25d29f2cde88cab85f7b59f5572c59b52a0009b1ce3a049e28c93015aa3bf9e078b7a9bdd8e8f679834d75ecc1a0b51ade9a2395ec4a783e1c0492492492492491314ebb23c23bcf1ac5161fdf8ec6a3d3dad7d11b69a06af999f93bb9004e1a7200848010163511fa3d0e8eecd5420bafaaec83756e73f6acbc3914c5e73b2b2a22d122ef600060848010158c3ae4bc6066210f95a43067af52664c1f4d45f3618f3a8febe64da69e91598000208480101a6bce8d8b17cdf7388cb73c7978ae03862d2fdc3cc227d34475f0a8d3cee738e00059da9d19b";

    #[test]
    fn test_master_proof() {
        let boc = HexBinary::from_hex(MASTER_PROOF).unwrap().to_vec();

        let tree_of_cells_parser = TreeOfCellsParser::default();

        let mut header = tree_of_cells_parser.parse_serialized_header(&boc).unwrap();

        let toc = tree_of_cells_parser
            .get_tree_of_cells(&boc, &mut header)
            .unwrap();

        println!("{}", header.root_idx);
        println!("{}", toc[0].special)
    }

    #[test]
    fn test_candidate_root_block() {
        let boc = HexBinary::from_hex(BOCS).unwrap().to_vec();

        let mut validator = Validator::default();
        validator.parse_candidates_root_block(&boc).unwrap();

        let validators: Vec<_> = validator
            .get_candidates_for_validators()
            .into_iter()
            .filter(|c| c.c_type != 0)
            .collect();

        println!("{}", validators.len());
    }
}
