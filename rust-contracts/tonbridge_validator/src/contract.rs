use cosmwasm_std::{entry_point, to_binary, Addr, HexBinary};
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
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
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
        ExecuteMsg::InitValidators {} => init_validators(deps, &info.sender),
        ExecuteMsg::SetValidatorSet {} => set_validator_set(deps),
        ExecuteMsg::VerifyValidators {
            root_hash,
            file_hash,
            vdata,
        } => verify_validators(deps, root_hash, file_hash, vdata),
        ExecuteMsg::AddCurrentBlockToVerifiedSet { root_hash } => {
            add_current_block_to_verified_set(deps, root_hash)
        }
        ExecuteMsg::ReadStateProof { boc, root_hash } => read_state_proof(deps, boc, root_hash),
        ExecuteMsg::ParseShardProofPath { boc } => parse_shard_proof_path(deps, boc),
    }
}

pub fn parse_candidates_root_block(deps: DepsMut, boc: String) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    validator.parse_candidates_root_block(HexBinary::from_hex(&boc)?.as_slice())?;
    VALIDATOR.save(deps.storage, &validator)?;
    Ok(Response::new().add_attributes(vec![("action", "parse_candidates_root_block")]))
}

pub fn init_validators(deps: DepsMut, sender: &Addr) -> Result<Response, ContractError> {
    let mut validator = Validator::default();
    validator.init_validators(deps, sender)?;
    Ok(Response::new().add_attributes(vec![("action", "init_validators")]))
}

pub fn set_validator_set(deps: DepsMut) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    validator.set_validator_set(deps.storage)?;
    Ok(Response::new().add_attributes(vec![("action", "set_validator_set")]))
}

pub fn verify_validators(
    deps: DepsMut,
    root_hash: String,
    file_hash: String,
    vdata: [VdataHex; 5],
) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    let vdata_bytes = vdata.map(|data| {
        let node_id = to_bytes32(&data.node_id).unwrap();
        let r = to_bytes32(&data.r).unwrap();
        let s = to_bytes32(&data.s).unwrap();

        // transform from hex string to bytes32
        Vdata { node_id, r, s }
    });
    validator.verify_validators(
        deps.storage,
        deps.api,
        to_bytes32(&root_hash)?,
        to_bytes32(&file_hash)?,
        &vdata_bytes,
    )?;
    Ok(Response::new().add_attributes(vec![("action", "verify_validators")]))
}

pub fn add_current_block_to_verified_set(
    deps: DepsMut,
    root_hash: String,
) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.add_current_block_to_verified_set(deps.storage, to_bytes32(&root_hash)?)?;
    Ok(Response::new().add_attributes(vec![("action", "add_current_block_to_verified_set")]))
}

pub fn read_state_proof(
    deps: DepsMut,
    boc: String,
    root_hash: String,
) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.read_state_proof(
        deps.storage,
        HexBinary::from_hex(&boc)?.as_slice(),
        to_bytes32(&root_hash)?,
    )?;
    Ok(Response::new().add_attributes(vec![("action", "read_state_proof")]))
}

pub fn parse_shard_proof_path(deps: DepsMut, boc: String) -> Result<Response, ContractError> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.parse_shard_proof_path(deps.storage, HexBinary::from_hex(&boc)?.as_slice())?;
    Ok(Response::new().add_attributes(vec![("action", "parse_shard_proof_path")]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::GetCandidatesForValidators {} => to_binary(&get_candidates_for_validators(deps)?),
        QueryMsg::GetValidators {} => to_binary(&get_validators(deps)?),
        QueryMsg::IsVerifiedBlock { root_hash } => to_binary(&is_verified_block(deps, root_hash)?),
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

pub fn is_verified_block(deps: Deps, root_hash: String) -> StdResult<bool> {
    let validator = VALIDATOR.load(deps.storage)?;
    validator.is_verified_block(deps.storage, to_bytes32(&root_hash)?)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
