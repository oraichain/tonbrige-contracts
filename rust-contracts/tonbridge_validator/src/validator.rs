use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Api, DepsMut, HexBinary, StdError, StdResult, Storage};
use tonbridge_parser::{
    bit_reader::to_bytes32,
    block_parser::ValidatorSet,
    tree_of_cells_parser::EMPTY_HASH,
    types::{Bytes32, ValidatorDescription, Vdata, VerifiedBlockInfo},
};
use tonbridge_validator::msg::UserFriendlyValidator;
use tonlib::cell::{BagOfCells, TonCellError};

use crate::{
    error::ContractError,
    signature_validator::{ISignatureValidator, SignatureValidator},
    state::{
        get_signature_candidate_validators, get_signature_validator_set, OWNER, VERIFIED_BLOCKS,
    },
};

pub trait IValidator {
    fn is_verified_block(&self, storage: &dyn Storage, root_hash: Bytes32) -> StdResult<bool>;
}

#[cw_serde]
#[derive(Default)]
pub struct Validator {
    pub signature_validator: SignatureValidator,
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

    pub fn get_validators(&self, storage: &dyn Storage) -> StdResult<ValidatorSet> {
        //  self.signature_validator.validator_set.to_owned()
        get_signature_validator_set(storage)
    }

    pub fn get_candidates_for_validators(&self, storage: &dyn Storage) -> StdResult<ValidatorSet> {
        // self.signature_validator
        //     .candidates_for_validator_set
        //     .to_owned()
        get_signature_candidate_validators(storage)
    }

    pub fn next_validator_updated(&self) -> bool {
        self.signature_validator.has_next
    }

    pub fn parse_candidates_root_block(
        &mut self,
        storage: &mut dyn Storage,
        boc: &[u8],
    ) -> Result<(), ContractError> {
        self.signature_validator
            .parse_candidates_root_block(storage, boc)?;
        Ok(())
    }

    pub fn init_validators(&mut self, storage: &mut dyn Storage) -> StdResult<()> {
        let key_block_root_hash = self.signature_validator.init_validators(storage)?;
        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };

        VERIFIED_BLOCKS.save(storage, &key_block_root_hash, &verified_block_info)
    }

    pub fn set_validator_set(&mut self, storage: &mut dyn Storage, api: &dyn Api) -> StdResult<()> {
        let key_block_root_hash = self.signature_validator.set_validator_set(storage, api)?;
        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };
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
        let test_root_hash = if self.signature_validator.root_hash == EMPTY_HASH {
            root_h
        } else {
            self.signature_validator.root_hash
        };
        self.signature_validator.verify_validators(
            storage,
            api,
            test_root_hash,
            file_hash,
            vdata,
        )?;
        Ok(())
    }

    pub fn verify_masterchain_block_by_validator_signatures(
        &self,
        storage: &mut dyn Storage,
        api: &dyn Api,
        boc: HexBinary,
        block_header_proof: HexBinary,
        file_hash: Bytes32,
        vdata: &[Vdata],
    ) -> Result<(), ContractError> {
        let block = BagOfCells::parse(boc.as_slice())?;
        let root = block.single_root()?;
        let block_header_proof = BagOfCells::parse(block_header_proof.as_slice())?;
        let root_hash_from_block_header = block_header_proof.root(0)?.reference(0)?.get_hash(0);
        let root_hash_from_block = root.get_hash(0);
        if root_hash_from_block.ne(&root_hash_from_block_header) {
            return Err(ContractError::TonCellError(
                TonCellError::cell_parser_error(
                    "Block header root hash from header proof does not match the root hash.",
                ),
            ));
        }

        let current_weight = self.signature_validator.verify_validators(
            storage,
            api,
            root_hash_from_block.as_slice().try_into()?,
            file_hash,
            vdata,
        )?;

        if current_weight * 3 <= self.signature_validator.sum_largest_total_weights * 2 {
            return Err(ContractError::Std(StdError::generic_err(&format!(
                "not enough votes to verify block. Wanted {:?}; has {:?}",
                self.signature_validator.sum_largest_total_weights * 2,
                current_weight * 3,
            ))));
        }

        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };
        VERIFIED_BLOCKS.save(
            storage,
            root_hash_from_block.as_slice().try_into()?,
            &verified_block_info,
        )?;
        Ok(())
    }

    pub fn add_current_block_to_verified_set(
        &self,
        storage: &mut dyn Storage,
        root_h: Bytes32,
    ) -> StdResult<()> {
        let validator_set = get_signature_validator_set(storage)?;
        let rh = self.signature_validator.add_current_block_to_verified_set(
            storage,
            root_h,
            validator_set,
        )?;
        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };
        VERIFIED_BLOCKS.save(storage, &rh, &verified_block_info)
    }

    pub fn verify_shard_blocks(
        &self,
        storage: &mut dyn Storage,
        shard_proof_links: Vec<HexBinary>,
        mc_block_root_hash: HexBinary,
    ) -> Result<(), ContractError> {
        if !self.is_verified_block(storage, to_bytes32(&mc_block_root_hash)?)? {
            return Err(ContractError::Std(StdError::generic_err(
                "masterchain block root hash is not verified",
            )));
        }
        for (i, proof_link) in shard_proof_links.iter().enumerate() {
            let cells = BagOfCells::parse(proof_link.as_slice())?;

            let root = cells.single_root()?;
            let first_ref = root.reference(0)?;
            let block = first_ref.load_block()?;
            let merkle_proof_root_hash = first_ref.get_hash(0);
            if i == 0 {
                if merkle_proof_root_hash.ne(&mc_block_root_hash.to_vec()) {
                    return Err(ContractError::Std(StdError::generic_err(
                        "merkle proof not verified",
                    )));
                }
                if block.extra.is_none() {
                    return Err(ContractError::Std(StdError::generic_err(
                        "There is no shard included in this masterchain block to verify.",
                    )));
                }
                let extra = block.extra.unwrap().custom.shards;
                for shards in extra.values() {
                    for shard in shards {
                        let mut verified_block = VerifiedBlockInfo::default();
                        verified_block.verified = true;
                        verified_block.seq_no = shard.seqno;
                        verified_block.start_lt = shard.start_lt;
                        verified_block.end_lt = shard.end_lt;
                        VERIFIED_BLOCKS.save(
                            storage,
                            shard.root_hash.as_slice().try_into()?,
                            &verified_block,
                        )?;
                    }
                }
            } else {
                if !self
                    .is_verified_block(storage, merkle_proof_root_hash.as_slice().try_into()?)?
                {
                    return Err(ContractError::Std(StdError::generic_err(
                        "The shard block root hash is not verified",
                    )));
                }
                if block.info.is_none() {
                    return Err(ContractError::Std(StdError::generic_err(
                        "There is no shard block info to collect prev block hash from.",
                    )));
                }
                let prev_ref = block.info.unwrap().prev_ref;
                if let Some(prev_blk) = prev_ref.first_prev {
                    let mut verified_block = VerifiedBlockInfo::default();
                    verified_block.verified = true;
                    verified_block.seq_no = prev_blk.seqno;
                    verified_block.end_lt = prev_blk.end_lt;
                    VERIFIED_BLOCKS.save(
                        storage,
                        prev_blk.root_hash.as_slice().try_into()?,
                        &verified_block,
                    )?;
                }
                if let Some(prev_blk) = prev_ref.second_prev {
                    let mut verified_block = VerifiedBlockInfo::default();
                    verified_block.verified = true;
                    verified_block.seq_no = prev_blk.seqno;
                    verified_block.end_lt = prev_blk.end_lt;
                    VERIFIED_BLOCKS.save(
                        storage,
                        prev_blk.root_hash.as_slice().try_into()?,
                        &verified_block,
                    )?;
                }
            }
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

        let block = VerifiedBlockInfo {
            seq_no,
            verified: true,
            ..Default::default()
        };

        VERIFIED_BLOCKS.save(deps_mut.storage, &root_hash, &block)
    }

    pub fn parse_user_friendly_validator(
        validator_description: ValidatorDescription,
    ) -> UserFriendlyValidator {
        UserFriendlyValidator {
            c_type: validator_description.c_type,
            weight: validator_description.weight,
            adnl_addr: HexBinary::from(&validator_description.adnl_addr),
            pubkey: HexBinary::from(&validator_description.pubkey),
            node_id: HexBinary::from(&validator_description.node_id),
        }
    }

    pub fn parse_user_friendly_validators(
        validator_set: ValidatorSet,
    ) -> Vec<UserFriendlyValidator> {
        validator_set
            .into_iter()
            .map(Validator::parse_user_friendly_validator)
            .collect()
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
    use tonbridge_parser::types::{Bytes32, Vdata, VerifiedBlockInfo};

    use super::Validator;

    const BOCS: &str = include_str!("testing/testdata/bocs.hex");
    const BOCS_LARGE: &str = include_str!("testing/testdata/bocs_large.hex");

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
    fn test_candidate_root_block() {
        let mut deps = mock_dependencies();
        let boc = HexBinary::from_hex(BOCS).unwrap().to_vec();

        let mut validator = Validator::default();
        validator
            .parse_candidates_root_block(deps.as_mut().storage, &boc)
            .unwrap();
        let root_hash = HexBinary::from(validator.signature_validator.root_hash);
        println!("root hash: {:?}", root_hash);

        let validators: Vec<_> = validator
            .get_candidates_for_validators(deps.as_ref().storage)
            .unwrap()
            .into_iter()
            .filter(|c| c.c_type != 0)
            .collect();

        // choose two random indexes for testing
        assert_eq!(
            HexBinary::from(validators[0].pubkey).to_hex(),
            "89462f768d318759a230f72ef92bdbcd02a09c791d40e6a01a53f42409e248a1".to_string()
        );
        assert_eq!(
            HexBinary::from(validators[5].pubkey).to_hex(),
            "76627b87a5717e9caab3a8044a8f75fd8da98b512c057e56defea91529f9b573".to_string()
        );
        assert_eq!(validators.len(), 14usize);
    }

    #[test]
    fn test_candidate_root_block_large() {
        let mut deps = mock_dependencies();
        let boc = HexBinary::from_hex(BOCS_LARGE).unwrap().to_vec();

        let mut validator = Validator::default();
        validator
            .parse_candidates_root_block(deps.as_mut().storage, &boc)
            .unwrap();

        let validators: Vec<_> = validator
            .get_candidates_for_validators(deps.as_ref().storage)
            .unwrap()
            .into_iter()
            .filter(|c| c.c_type != 0)
            .collect();
        validator.init_validators(deps.as_mut().storage).unwrap();

        // choose two random indexes for testing
        assert_eq!(validators.len(), 343usize);
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
