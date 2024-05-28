use std::array::TryFromSliceError;

use cosmwasm_std::{entry_point, to_binary, Addr, HexBinary, StdError};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use tonbridge_parser::bit_reader::to_bytes32;
use tonbridge_parser::types::{Vdata, VdataHex};
use tonbridge_validator::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg, UserFriendlyValidator,
};

use crate::error::ContractError;
use crate::state::{OWNER, VALIDATOR};
use crate::validator::{IValidator, Validator};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let mut validator = Validator::default();
    if let Some(boc) = msg.boc {
        validator.parse_candidates_root_block(boc.as_slice())?;
        validator.init_validators(deps.storage)?;
    }
    VALIDATOR.save(deps.storage, &validator)?;
    OWNER.set(deps, Some(info.sender))?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ParseCandidatesRootBlock { boc } => parse_candidates_root_block(deps, boc),
        ExecuteMsg::ResetValidatorSet { boc } => reset_validator_set(deps, &info.sender, boc),
        // ExecuteMsg::SetValidatorSet {} => set_validator_set(deps),
        ExecuteMsg::VerifyValidators {
            root_hash,
            file_hash,
            vdata,
        } => verify_validators(deps, root_hash, file_hash, vdata),
        // ExecuteMsg::AddCurrentBlockToVerifiedSet { root_hash } => {
        //     add_current_block_to_verified_set(deps, root_hash)
        // }
        ExecuteMsg::ReadMasterProof { boc } => read_master_proof(deps, boc),
        ExecuteMsg::ReadStateProof { boc, root_hash } => read_state_proof(deps, boc, root_hash),
        ExecuteMsg::ParseShardProofPath { boc } => parse_shard_proof_path(deps, boc),
        ExecuteMsg::SetVerifiedBlock { root_hash, seq_no } => {
            set_verified_block(deps, &info.sender, root_hash, seq_no)
        }
        ExecuteMsg::ParsePartValidators { boc } => parse_part_validators(deps, boc),
    }
}

pub fn parse_candidates_root_block(
    deps: DepsMut,
    boc: HexBinary,
) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    validator.parse_candidates_root_block(boc.as_slice())?;
    VALIDATOR.save(deps.storage, &validator)?;
    Ok(Response::new().add_attributes(vec![("action", "parse_candidates_root_block")]))
}

// this entrypoint is used mostly for testing or initialization
// where the admin knows the given validator set is already valid.
pub fn reset_validator_set(
    deps: DepsMut,
    sender: &Addr,
    boc: HexBinary,
) -> Result<Response, ContractError> {
    OWNER.assert_admin(deps.as_ref(), sender)?;
    let storage = deps.storage;
    let mut validator = VALIDATOR.load(storage)?;

    // update new candidates given the new block data
    validator.parse_candidates_root_block(boc.as_slice())?;

    // skip verification and assume the new validator set is valid (only admin can call this)
    validator.init_validators(storage)?;

    // store the validator set in cache
    VALIDATOR.save(storage, &validator)?;
    Ok(Response::new().add_attributes(vec![("action", "reset_validator_set")]))
}

// should be called by relayers
pub fn verify_validators(
    deps: DepsMut,
    root_hash: HexBinary,
    file_hash: HexBinary,
    vdata: Vec<VdataHex>,
) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    let vdata_bytes = vdata
        .iter()
        .map(|data| {
            let node_id = to_bytes32(&data.node_id).unwrap();
            let r = to_bytes32(&data.r).unwrap();
            let s = to_bytes32(&data.s).unwrap();

            // transform from hex string to bytes32
            Vdata { node_id, r, s }
        })
        .collect::<Vec<Vdata>>();
    validator.verify_validators(
        deps.storage,
        deps.api,
        to_bytes32(&root_hash)?,
        to_bytes32(&file_hash)?,
        &vdata_bytes,
    )?;
    validator.set_validator_set(deps.storage)?;
    VALIDATOR.save(deps.storage, &validator)?;
    Ok(Response::new().add_attributes(vec![("action", "verify_validators")]))
}

// this function is probably rarely used
// since it simply adds a new block into the set of verified blocks given that the validators have validated it.
// pub fn add_current_block_to_verified_set(
//     deps: DepsMut,
//     root_hash: String,
// ) -> Result<Response, ContractError> {
//     let validator = VALIDATOR.load(deps.storage)?;
//     validator.add_current_block_to_verified_set(deps.storage, to_bytes32(&root_hash)?)?;
//     Ok(Response::new().add_attributes(vec![("action", "add_current_block_to_verified_set")]))
// }

pub fn read_master_proof(deps: DepsMut, boc: HexBinary) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.read_master_proof(deps.storage, boc.as_slice())?;
    Ok(Response::new().add_attributes(vec![("action", "read_master_proof")]))
}

pub fn read_state_proof(
    deps: DepsMut,
    boc: HexBinary,
    root_hash: HexBinary,
) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.read_state_proof(deps.storage, boc.as_slice(), to_bytes32(&root_hash)?)?;
    Ok(Response::new().add_attributes(vec![("action", "read_state_proof")]))
}

pub fn parse_shard_proof_path(deps: DepsMut, boc: HexBinary) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.parse_shard_proof_path(deps.storage, boc.as_slice())?;
    Ok(Response::new().add_attributes(vec![("action", "parse_shard_proof_path")]))
}

// this entrypoint is used mostly for testing or initialization
// where the admin knows the given block is surely verified.
pub fn set_verified_block(
    deps: DepsMut,
    caller: &Addr,
    root_hash: HexBinary,
    seq_no: u32,
) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.set_verified_block(deps, caller, to_bytes32(&root_hash)?, seq_no)?;
    Ok(Response::new().add_attributes(vec![("action", "set_verified_block")]))
}

pub fn parse_part_validators(deps: DepsMut, boc: HexBinary) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    validator.parse_part_validators(boc.as_slice())?;
    Ok(Response::new().add_attributes(vec![("action", "parse_part_validators")]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::GetCandidatesForValidators {} => to_binary(&get_candidates_for_validators(deps)?),
        QueryMsg::GetValidators {} => to_binary(&get_validators(deps)?),
        QueryMsg::IsVerifiedBlock { root_hash } => to_binary(&is_verified_block(deps, root_hash)?),
        QueryMsg::IsSignedByValidator {
            validator_node_id,
            root_hash,
        } => to_binary(&is_signed_by_validator(deps, validator_node_id, root_hash)?),
    }
}

pub fn get_config(deps: Deps) -> StdResult<ConfigResponse> {
    let owner = OWNER.query_admin(deps)?;
    Ok(ConfigResponse { owner: owner.admin })
}

pub fn get_candidates_for_validators(deps: Deps) -> StdResult<Vec<UserFriendlyValidator>> {
    let validator = VALIDATOR.load(deps.storage)?;
    let result = validator.get_candidates_for_validators();
    Ok(validator.parse_user_friendly_validators(result))
}

pub fn get_validators(deps: Deps) -> StdResult<Vec<UserFriendlyValidator>> {
    let validator = VALIDATOR.load(deps.storage)?;
    let result = validator.get_validators();
    Ok(validator.parse_user_friendly_validators(result))
}

pub fn is_verified_block(deps: Deps, root_hash: HexBinary) -> StdResult<bool> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.is_verified_block(
        deps.storage,
        root_hash
            .as_slice()
            .try_into()
            .map_err(|err: TryFromSliceError| StdError::generic_err(err.to_string()))?,
    )
}

pub fn is_signed_by_validator(
    deps: Deps,
    validator_node_id: HexBinary,
    root_hash: HexBinary,
) -> StdResult<bool> {
    let validator = VALIDATOR.load(deps.storage)?;
    Ok(validator.is_signed_by_validator(
        deps.storage,
        to_bytes32(&validator_node_id)?,
        to_bytes32(&root_hash)?,
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
