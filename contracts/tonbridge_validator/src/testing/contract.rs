#[cfg(test)]
mod tests {

    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, DepsMut, HexBinary, StdError,
    };
    use cw_controllers::AdminError;
    use std::{fs::File, io::Read};
    use tonbridge_parser::{
        types::{Bytes32, VdataHex, VerifiedBlockInfo},
        EMPTY_HASH,
    };
    use tonbridge_validator::msg::{ExecuteMsg, QueryMsg, UserFriendlyValidator};

    use crate::{
        contract::{execute, query},
        error::ContractError,
        state::{OWNER, VALIDATOR, VERIFIED_BLOCKS},
        validator::Validator,
    };

    const BLOCK_BOCS_SMALL: &str = include_str!("testdata/bocs.hex");
    const BLOCK_BOCS_LARGE: &str = include_str!("testdata/bocs_large.hex");
    const KEY_BLOCK_WITH_NEXT_VAL: &str = include_str!("testdata/keyblock_with_next_val.hex");

    #[cw_serde]
    pub struct VdataSring {
        node_id: String,
        r: String,
        s: String,
    }

    #[test]
    fn test_prepare_new_key_block() {
        let mut deps = mock_dependencies();
        let boc = HexBinary::from_hex(BLOCK_BOCS_SMALL).unwrap();

        VALIDATOR
            .save(deps.as_mut().storage, &Validator::default())
            .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &vec![]),
            ExecuteMsg::PrepareNewKeyBlock { keyblock_boc: boc },
        )
        .unwrap();

        let validators_bin = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetCandidatesForValidators {
                start_after: None,
                limit: Some(30),
                order: None,
            },
        )
        .unwrap();

        let validators: Vec<UserFriendlyValidator> = from_binary(&validators_bin).unwrap();

        // choose two random indexes for testing
        assert_eq!(
            validators
                .iter()
                .find(|val| val.pubkey.to_hex()
                    == "89462f768d318759a230f72ef92bdbcd02a09c791d40e6a01a53f42409e248a1"
                        .to_string())
                .is_some(),
            true,
        );
        assert_eq!(
            validators
                .iter()
                .find(|val| val.pubkey.to_hex()
                    == "76627b87a5717e9caab3a8044a8f75fd8da98b512c057e56defea91529f9b573"
                        .to_string())
                .is_some(),
            true,
        );
        assert_eq!(validators.len(), 14usize);
    }

    #[test]
    fn test_verify_key_block() {
        let mut deps = mock_dependencies();
        let boc = HexBinary::from_hex(BLOCK_BOCS_SMALL).unwrap();

        VALIDATOR
            .save(deps.as_mut().storage, &Validator::default())
            .unwrap();

        // case 1: empty root hash
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &vec![]),
            ExecuteMsg::VerifyKeyBlock {
                root_hash: EMPTY_HASH.as_slice().try_into().unwrap(),
                file_hash: EMPTY_HASH.as_slice().try_into().unwrap(),
                vdata: vec![],
            },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::Std(StdError::generic_err("wrong root_hash or file_hash")).to_string()
        );

        // prepare keyblock to populate new root hash
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &vec![]),
            ExecuteMsg::PrepareNewKeyBlock { keyblock_boc: boc },
        )
        .unwrap();

        // case 2: even after preparing keyblock, if file hash is empty -> still return error
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &vec![]),
            ExecuteMsg::VerifyKeyBlock {
                root_hash: EMPTY_HASH.as_slice().try_into().unwrap(),
                file_hash: EMPTY_HASH.as_slice().try_into().unwrap(),
                vdata: vec![],
            },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::Std(StdError::generic_err("wrong root_hash or file_hash")).to_string()
        );
    }

    #[test]
    fn test_reset_validator_set() {
        let mut deps = mock_dependencies();
        let boc = HexBinary::from_hex(BLOCK_BOCS_SMALL).unwrap();

        VALIDATOR
            .save(deps.as_mut().storage, &Validator::default())
            .unwrap();

        OWNER
            .set(deps.as_mut(), Some(Addr::unchecked("admin")))
            .unwrap();

        // suite 1: should fail since not an admin
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("relayer", &vec![]),
            ExecuteMsg::ResetValidatorSet { boc: boc.clone() },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            ContractError::AdminError(AdminError::NotAdmin {}).to_string()
        );

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &vec![]),
            ExecuteMsg::ResetValidatorSet { boc },
        )
        .unwrap();

        // query validator list, should return some validators
        let validators: Vec<UserFriendlyValidator> = from_binary(
            &query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetValidators {
                    start_after: None,
                    limit: Some(30),
                    order: None,
                },
            )
            .unwrap(),
        )
        .unwrap();

        // choose two random indexes for testing
        assert_eq!(
            validators
                .iter()
                .find(|val| val.pubkey.to_hex()
                    == "89462f768d318759a230f72ef92bdbcd02a09c791d40e6a01a53f42409e248a1"
                        .to_string())
                .is_some(),
            true,
        );
        assert_eq!(
            validators
                .iter()
                .find(|val| val.pubkey.to_hex()
                    == "76627b87a5717e9caab3a8044a8f75fd8da98b512c057e56defea91529f9b573"
                        .to_string())
                .is_some(),
            true,
        );
        assert_eq!(validators.len(), 14usize);

        // after reset, the candidate list should be empty
        let candidates: Vec<UserFriendlyValidator> = from_binary(
            &query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetCandidatesForValidators {
                    start_after: None,
                    limit: Some(30),
                    order: None,
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_verify_master_chain_block() {
        // https://scan.orai.io/txs/87D34F1686292B1B34EEDD36EA0D6345035C5EC2D5BA2219AA5292ECA03351DB
        let mut deps = mock_dependencies();
        VALIDATOR
            .save(deps.as_mut().storage, &Validator::default())
            .unwrap();

        OWNER
            .set(deps.as_mut(), Some(Addr::unchecked("admin")))
            .unwrap();

        let boc = HexBinary::from_hex(BLOCK_BOCS_LARGE).unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &vec![]),
            ExecuteMsg::ResetValidatorSet { boc },
        )
        .unwrap();

        let mut file = File::open("src/testing/testdata/masterchain_block_sig.json").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let v_data_string: Vec<VdataSring> = serde_json_wasm::from_str(&contents).unwrap();

        //parse vdata string to vdata hex
        let v_data_hex: Vec<VdataHex> = v_data_string
            .iter()
            .map(|item| VdataHex {
                node_id: HexBinary::from_hex(&item.node_id).unwrap(),
                r: HexBinary::from_hex(&item.r).unwrap(),
                s: HexBinary::from_hex(&item.s).unwrap(),
            })
            .collect();

        let block_header = HexBinary::from_hex("b5ee9c72010209010001fa00094603f7a9db0094cdcb49e027f44e85ce4af164d8acaef2c0c2feaba1577a1d0091d1001601241011ef55aaffffff110203040501a09bc7a987000000000401024d18e30000000100ffffffff0000000000000000667b8b4c00002b0e663fe54000002b0e663fe5444ea6e53c0008d5a6024d18df024d092bc400000007000000000000002e0628480101ddd42acf06126e1d8942bdb8080fdd97a7dae4d6df7880ee9625d69da1502a7d00032a8a04c99e099aeb852551a3d8a6efdb41e035cac018611ac5352a6c30393482aa62a5501b3f48c250cea26fd284425c3810466a214872a4b398c9957ce9787f58e264016f016f0708284801016429d9dc8a7cc6e5d82344adf804bfa345c3121b7fb025e29635dbc8360187030007009800002b0e6630a304024d18e2b34aa8d3e01de0b4e6a0f9c052636a095d5dc32d9d25e5a22875bbe4c0ab5016d91bcb8d91d4f573b3acad3fcce8fe3e3f74cfd27099f0776e73aa7467ae0e9b688c0103c99e099aeb852551a3d8a6efdb41e035cac018611ac5352a6c30393482aa62a560d14b21173ec6f4f4448b704abfbae237f3d0f1b13daad08cc039927de7bb12016f0014688c0103501b3f48c250cea26fd284425c3810466a214872a4b398c9957ce9787f58e2648a80218fbb55d4759795d9df7ab9a3dd5dbcc403a2dff4ae5f53ed1d382a635a016f0014").unwrap();
        let file_hash =
            HexBinary::from_hex("36f5e7b74e779744135fa533b18da8a7649786eaf43be6b770d211e28b6493e8")
                .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &vec![]),
            ExecuteMsg::VerifyMasterchainBlockByValidatorSignatures {
                block_header_proof: block_header,
                file_hash,
                vdata: v_data_hex,
            },
        )
        .unwrap();

        let root_hash: Bytes32 = [
            247, 169, 219, 0, 148, 205, 203, 73, 224, 39, 244, 78, 133, 206, 74, 241, 100, 216,
            172, 174, 242, 192, 194, 254, 171, 161, 87, 122, 29, 0, 145, 209,
        ];

        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };

        assert_eq!(
            VERIFIED_BLOCKS
                .load(deps.as_mut().storage, &root_hash)
                .unwrap(),
            verified_block_info
        );
    }

    #[test]
    fn test_verify_shard_block() {
        //https://scan.orai.io/txs/CBAF849259540943A1744125A170A40E811CDDAC7CB37E33459089D24808159A
        let mut deps = mock_dependencies();
        VALIDATOR
            .save(deps.as_mut().storage, &Validator::default())
            .unwrap();

        OWNER
            .set(deps.as_mut(), Some(Addr::unchecked("admin")))
            .unwrap();

        let shard_proof_links =  vec![HexBinary::from_hex("b5ee9c720102100100021f00094603f7a9db0094cdcb49e027f44e85ce4af164d8acaef2c0c2feaba1577a1d0091d1001601241011ef55aaffffff110203040528480101905221fe224f53b5280218e04d4bff53580cda37eef65cb6552f23f120feb3a7000128480101ddd42acf06126e1d8942bdb8080fdd97a7dae4d6df7880ee9625d69da1502a7d000328480101c06d83c70ff5d12aaa77b27af0393eab021f23560233752485aa27f3f0f89b34001524894a33f6fd06e1c1b9977c7e4d70cee9d1f03b0296ee9eed2fa5ae53b6af013110e3ba7142f6b51f5af132fb679b880f948118527384b5c963eb79ed712b7393f075da3c5ec00607080928480101e5c2351f39f162b4ed171487762bfa80fdcb0b97ed56bc32b3f70a45e6648a2d000400010228480101e5bd1283a2f8b22826ac42d96d13fe42f9c1564158733312ce62d5db62ae033300062317cca568e933962a43b9aca0040a0b0c0103d0400d003fb000000000400000000000000023a4ce58a90ee6b28008e933962a43b9aca0042101500f01db5015172c101268c718000158733090f400000158733090f50810d87a0df0b9c369b6aff857495a5734b96abb63dcd160992cc28c770fdbcc88f51460eaf31c824e2e4a685576d8a4a44775d38bd02b81892e6e9ff32b340f78000046d9ec00000000000000001268c6fb33dc5a1a0e001347499cb1521dcd65002028480101a06136b8165a8c76a521df114d69b8f17af3dfb6bed0f0cc7e66dff1ace379750003").unwrap()];
        let mc_block_root_hash =
            HexBinary::from_hex("f7a9db0094cdcb49e027f44e85ce4af164d8acaef2c0c2feaba1577a1d0091d1")
                .unwrap();
        let root_hash: Bytes32 = mc_block_root_hash.as_slice().try_into().unwrap();

        let verified_block_info = VerifiedBlockInfo {
            verified: true,
            ..Default::default()
        };
        // case 1, mc_block_root_hash not verify
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &vec![]),
            ExecuteMsg::VerifyShardBlocks {
                shard_proof_links: shard_proof_links.clone(),
                mc_block_root_hash: mc_block_root_hash.clone(),
            },
        )
        .unwrap_err();

        // case 2: success
        VERIFIED_BLOCKS
            .save(deps.as_mut().storage, &root_hash, &verified_block_info)
            .unwrap();
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &vec![]),
            ExecuteMsg::VerifyShardBlocks {
                shard_proof_links,
                mc_block_root_hash,
            },
        )
        .unwrap();
    }
}
