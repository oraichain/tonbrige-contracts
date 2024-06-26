#[cfg(test)]
mod tests {

    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, HexBinary, StdError,
    };
    use cw_controllers::AdminError;
    use tonbridge_parser::EMPTY_HASH;
    use tonbridge_validator::msg::{ExecuteMsg, QueryMsg, UserFriendlyValidator};

    use crate::{
        contract::{execute, query},
        error::ContractError,
        state::{OWNER, VALIDATOR},
        validator::Validator,
    };

    const BLOCK_BOCS_SMALL: &str = include_str!("testdata/bocs.hex");

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
}
