use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Api, DepsMut, HexBinary, StdError, StdResult, Storage};
use tonbridge_parser::{
    block_parser::ValidatorSet20,
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser, EMPTY_HASH},
    types::{Bytes32, CachedCell, ValidatorDescription, Vdata, VerifiedBlockInfo},
};
use tonbridge_validator::{
    msg::UserFriendlyValidator,
    shard_validator::{IShardValidator, ShardValidator},
};

use crate::{
    signature_validator::{ISignatureValidator, SignatureValidator},
    state::{OWNER, VERIFIED_BLOCKS},
};

pub trait IValidator {
    fn is_verified_block(&self, storage: &dyn Storage, root_hash: Bytes32) -> StdResult<bool>;
}

#[cw_serde]
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

    pub fn init_validators(&mut self, storage: &mut dyn Storage) -> StdResult<()> {
        let key_block_root_hash = self.signature_validator.init_validators()?;
        let mut verified_block_info = VerifiedBlockInfo::default();
        verified_block_info.verified = true;

        VERIFIED_BLOCKS.save(storage, &key_block_root_hash, &verified_block_info)
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
        vdata: &[Vdata],
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
        boc: &[u8],  // older block data
        rh: Bytes32, // newer root hash
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
        OWNER
            .assert_admin(deps, caller)
            .map_err(|err| StdError::generic_err(err.to_string()))?;
        if self.is_verified_block(deps.storage, root_hash)? {
            return Err(StdError::generic_err("block already verified"));
        }

        let mut block = VerifiedBlockInfo::default();
        block.verified = true;
        block.seq_no = seq_no;

        VERIFIED_BLOCKS.save(deps_mut.storage, &root_hash, &block)
    }

    pub fn parse_user_friendly_validator(
        &self,
        validator_description: ValidatorDescription,
    ) -> UserFriendlyValidator {
        UserFriendlyValidator {
            c_type: validator_description.c_type,
            weight: validator_description.weight,
            adnl_addr: HexBinary::from(&validator_description.adnl_addr).to_hex(),
            pubkey: HexBinary::from(&validator_description.pubkey).to_hex(),
            node_id: HexBinary::from(&validator_description.node_id).to_hex(),
        }
    }

    pub fn parse_user_friendly_validators(
        &self,
        validator_description: [ValidatorDescription; 20],
    ) -> Vec<UserFriendlyValidator> {
        validator_description
            .map(|candidate| self.parse_user_friendly_validator(candidate))
            .to_vec()
    }
}

impl IValidator for Validator {
    fn is_verified_block(&self, storage: &dyn Storage, root_hash: Bytes32) -> StdResult<bool> {
        Ok(VERIFIED_BLOCKS
            .may_load(storage, &root_hash)?
            .unwrap_or_default()
            .verified)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::mock_dependencies, HexBinary};
    use tonbridge_parser::{
        tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
        types::{Bytes32, Vdata, VerifiedBlockInfo},
    };

    use super::Validator;

    const MASTER_PROOF :&str = "b5ee9c72c102070100011500000e0034005a00a300c900ef0115241011ef55aafffffffd010203062848010157d5d40d6835fb10eab860add2c9ed9384007cbd5c4af7006716f5eeb6109092000128480101c3b6883898411dde154d6b1040de039f6adcb180ce452ba14459b202a7be8bd600030a8a045525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e36184f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f001f0405284801015525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e3618001f284801014f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f284801011ca3e8075b0f29141deae260b25832844ffdaea9e42d41e9c62f0bf875a132d800075572e271";
    const BOCS:&str = "b5ee9c72410234010007c900041011ef55aafffffffd0103040501a09bc7a987000000000601004262100000000000ffffffff000000000000000063566c62000004d23f800dc0000004d23f800dc708fd4f290000df980042620d00425a75c400000003000000000000002e0208480101622689df2205931afa1d7c115f79f8fac4ea73f4edb05fabdca81c020f22a6130000084801012dfc806d1c50694678c34d5816e9316a00b94b05e085b5f97db07e9d8883040a0003084801011a6a28d6cea96f567bc6cd7da3ef88328865235ddd97386477d1436ce553595a001a04894a33f6fd5efff688d3a3cb98a24a4a498c8a67fd66e28a75139bf8363cd39ba56ebafdbedc9fcfce7dd2bf882a6833fb941d6e10bdc82bd9b2a4d123d114b81dde215c54c00607080908480101d72c3cbab4c1aded3d3342b743ec8f1f87d3d2656c439d39eccd5bab779c48e2000c08480101145ebae9f5d86e55979e5b6fcc1be5e39d70001e487d40a0bc4773b802c0fe4b000c08480101aef4bc8f76ad0dfb68e5a5c151d0fb544f45483ed32cacafde88ddb50a1121da000e0457cca5e87735940043b9aca002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac0a0b0c0d08480101501d1b77377edb7e682530a6ea1678615080b4bd76d9b1591b6c921688b02a12000208480101e18e1a1a40f3e0ccfcc3fc904f6ae42006e9e1c78ce6ef4bbffbf7d6e3770895000008480101f510fd883f3bd56c0f3e7cb3ab4684b225b34998cbea82a9a3e446d2dde602a300040201200e330202d80f320201201011084801018a67f6328db6b01c422c97114927cd9f39ca6e9578d437debecdf1091a4e98d7000d020162123102012013140848010162c1ea84ef6c2221181abacda0baff83ac88e6d3dd77f16ce981319739dcdf70000601014815012b12635650f663566d16000e000e0ffffffffffffff8c0160202cc1726020120181f020120191c0201201a1b009b1ce3a049e2a2518bdda34c61d6688c3dcbbe4af6f340a8271e475039a80694fd090278922840492492492492493b0391252e60a1cf81bbacde546f1e2805087fc291d5da465d963bc14e53df9060009b1ce3a049e2aaeb6babda7e323ceb3052c9361f70c7c7e12ed7e64f1935df83ca21d0c30ca4c0492492492492491d24bbd188fe0ffa6fe5affaed46c3913b84d00011c04c9bf6e3a576387144c2e00201201d1e009b1ce3a049e2a7fa088020c2a7fdfa4a91c0aac7a69c3826ff06394142059cf5893fa442bbd800492492492492492d2eaf1e23aac0ed093523bcd157e2fc7bc76ec0f3777a0772a25a9d493f9338a0009b1ce3a049e28e87ef1aac2280bf5fbf1869d0bb94ac94c9a7f2922b757b41968231a7d0bff70049249249249249154e4c591dc8671e0169285fbf6dbf498a767668892de738e800cdc902660378e002012020230201202122009b1ce3a049e2b714cbc17f2056cc2123f17ad04ce3a8e19da0627da7f27ac6246038fe66ee3e404924924924924903e69b47ddd935888b818916e6ef5be4323655182b6c93dd8ab5f902b2f12584e0009b1ce3a049e29d989ee1e95c5fa72aacea0112a3dd7f636a62d44b015f95b7bfaa454a7e6d5cc04924924924924919f259fff0b013a108033f9f5e92a0f76940f8841876ff02b0f7142c2c79bdbc200201202425009b1ce3a049e2b727f3f39f74afe20a9a0cfee5075b842f720af66ca93448f4452e0777885715004924924924924917b92409e2a3f8307539cefb50b14617198615bbe5de202fefe644c72588260460009b1ce3a049e29d21582596bfcc6d1de358003ef042e5207f4c804d7a1c7eb4df45e61dcb12bac0492492492492492632154ae74d72cbf208021b88ec8d3d89a3fcc246e6532354b918b784c81030a0020120272e020120282b020120292a009b1ce3a049e2bb5203d6b26731acaa20369ddcf706ef8a861473e9c00fe2051695440e366cb9804924924924924924d365a568e1356f3d7e3b9949501619745721ca7cf0feb0fad4d2f8847c283020009b1ce3a049e2b5e9e4f9e2be0699846cd5462dd33c0db38ed1e20a8e2b5a11ea6d6fd71eb35b80492492492492493d7579a885d03932c5eba75600dceb15b9b2ae4968d27b4b80c640d6bfe60615a00201202c2d009b1ce3a049e2a25935e71c9cf1b50eadc3bb29e330df9cea0d3b68cd6aff8eedc2659ccab428404924924924924902cdb4413b9ee19a9b2db5e70ac0e41126747c2fee2edd6f2a224f09cf8d6be1e0009b1ce3a049e2b0b092e100a69d80c496cbb06414bc2512888a9c398315ad596b57764098164cc0492492492492491a0b69ee5777de48e854d7d2af8d143b0e0ab1930204b4f9e3a0ec57c2722f57e00201482f30009b1ce3a049e280d5bc09be3be73173d7e7cf402cc5706e9b4f1e5328331252638d4b6e187161004924924924924910d373d1795c02c745f16012330554d25d29f2cde88cab85f7b59f5572c59b52a0009b1ce3a049e28c93015aa3bf9e078b7a9bdd8e8f679834d75ecc1a0b51ade9a2395ec4a783e1c0492492492492491314ebb23c23bcf1ac5161fdf8ec6a3d3dad7d11b69a06af999f93bb9004e1a7200848010163511fa3d0e8eecd5420bafaaec83756e73f6acbc3914c5e73b2b2a22d122ef600060848010158c3ae4bc6066210f95a43067af52664c1f4d45f3618f3a8febe64da69e91598000208480101a6bce8d8b17cdf7388cb73c7978ae03862d2fdc3cc227d34475f0a8d3cee738e00059da9d19b";

    fn convert_byte32(str: &str) -> Bytes32 {
        HexBinary::from_hex(str)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_default_verified_blocks_info() {
        let default_block_info = VerifiedBlockInfo::default();
        assert_eq!(default_block_info.verified, false);
    }

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
        println!(
            "val pubkey: {:?}",
            HexBinary::from(validators[0].pubkey).to_hex()
        );
    }

    #[test]
    fn test_verify_signature() {
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
            Vdata {
                node_id: convert_byte32(
                    "199c16d7f28b0197f3f2ab65c638c96161ee94358adf59cbbc3ee6e6d862d378",
                ),
                r: convert_byte32(
                    "1d46c3aea932eeed3bc0ab79a34a2b3e9347de1502817359d2f676203a83edcd",
                ),
                s: convert_byte32(
                    "250a26875f96f704288b5ef9f100c254b13dd49e82af546c76ca9bcb03178e09",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "60d70c53335319040b7cfc5e3862b91e63d5f2da80cd9a9a001c3340514fe313",
                ),
                r: convert_byte32(
                    "c0faa7b074d35f3128b4ed4a26674812fda07368c7e08e60ec6532572f3539e3",
                ),
                s: convert_byte32(
                    "574fe6b40a3e8278938c4a5b84de3feda93c3dde7f63db2029e6a6864a530f06",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "2cf18f60a038f4d0b40cfd6b3a817dfcb5f10cd9076060570decd4e72699d48b",
                ),
                r: convert_byte32(
                    "4421e89e7b1441f09b8a585e59ab1a46f700883315d90f297ab2366ea9f893bd",
                ),
                s: convert_byte32(
                    "a261653466c82353a3ea9e700dbd5d69d506a2aef2bc9f3ff6fe80ea7607cb04",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "d0350114c9d3802ecc5d9b13d36f81c21b8d55bd161c6a8a1e72afed52fd9445",
                ),
                r: convert_byte32(
                    "d94ecf69fb3b8ab3db4f325a02f0a881449e758b826415be23df9fee788affda",
                ),
                s: convert_byte32(
                    "bf99c59910d32abe67d06899a068880bb08566d60ade9e5ccffc09819b96b802",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "578ea0f289f4047d9dcade46d48f89477fc56936f8fe3689db13c50e768c6b39",
                ),
                r: convert_byte32(
                    "a45bbbfe3d57c69da2169b3de8e044e3cca61159b486c3a4b90f072ed643a442",
                ),
                s: convert_byte32(
                    "3366c3c2983b4773820970e50d1343ae71775c6aafd7723bbe9e3d2146fc7706",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "614d8fffba1c3029c1eec9c2396c6f06c8b4abbab60fd92470b66b724736a042",
                ),
                r: convert_byte32(
                    "77e9894daf3c68bdeb38bd753b28ef38f23496137c8951982c2d830aaf2d4df0",
                ),
                s: convert_byte32(
                    "9db86bd6a7a4944688f425e90ec237c1d844675f4541dc70e9f5b88a9c62410a",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "65142da29a4f7da4c0d5f4dd783b68c9f44bfc5dac84175a592d32fb1c0e87ef",
                ),
                r: convert_byte32(
                    "9e0eee7b12efcb229f41e74ac674c3ddc9ae9691ee0460f70efb66d7261607d2",
                ),
                s: convert_byte32(
                    "dafa671c45df902dc126b679ab89d671686e182cb3191ff430982b22f2f97404",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "2a525ef4e988e499cd84cfac2f8939ac67166c17f54b12295195ec746eaa709b",
                ),
                r: convert_byte32(
                    "f9e5dc1bd1567758def8a7913f46d045d33163d19860e1632a33d50b7acc00ce",
                ),
                s: convert_byte32(
                    "0ab80f74fb97ce3af44dc4e3076d0f43ab0cb20edfafa476936b63813e61990c",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "df638202e3546b20cfad3b6eb6a6ffcd63133cf35adac1b60bc336675e4d370a",
                ),
                r: convert_byte32(
                    "2bbc7a3ff43193669398f535e84928f19301a838a2184d0ef7c89d74ba97f1be",
                ),
                s: convert_byte32(
                    "ba96a7b430117b5bf2f4837fe127e739c0c451065e6311ed7efdcb17736a6b0d",
                ),
            },
            Vdata {
                node_id: convert_byte32(
                    "cc25487e69c7356beb69316023f260b5200c71032d9918371c82e2aea42107d5",
                ),
                r: convert_byte32(
                    "3b4fbef0048da69527b9f23e066f9b1f8b30dd524e6764d4b49dd9f0b32f6463",
                ),
                s: convert_byte32(
                    "65ac370f7354ef3c2ed79f0afa83fc058cdd6db337a5ce1e5aa0cd1f2426b70c",
                ),
            },
        ];

        let root_hash =
            convert_byte32("292edb12dadb1b56db5c44687bf1311dcac38089f8b895b11bf0c8fbd605989e");
        let file_hash =
            convert_byte32("dfd3c0f265e62f340cb8020a0a3b5d0503d71ca84d5f40b2372e858147c03ba1");

        let mut deps = mock_dependencies();
        let validator = Validator::default();
        validator
            .verify_validators(
                &mut deps.storage,
                &deps.api,
                root_hash,
                file_hash,
                &signatures,
            )
            .unwrap();

        let err = validator
            .add_current_block_to_verified_set(&mut deps.storage, root_hash)
            .unwrap_err();

        assert!(err.to_string().contains("not enough votes"));

        // for (let i = 0; i < signatures.length; i++) {
        //   expect(
        //     await validator.isSignedByValidator(
        //       "0x" + signatures[i].node_id,
        //       updateValidatorsRootHash
        //     )
        //   ).to.be.equal(true);
        // }
    }
}
