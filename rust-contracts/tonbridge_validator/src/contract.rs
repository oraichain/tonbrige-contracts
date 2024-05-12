use cosmwasm_std::{entry_point, to_binary, Addr};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use tonbridge_validator::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg, UserFriendlyValidator,
};

use crate::error::ContractError;
use crate::state::{OWNER, VALIDATOR};
use crate::validator::Validator;

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
    }
}

pub fn parse_candidates_root_block(deps: DepsMut, boc: Binary) -> Result<Response, ContractError> {
    let mut validator = VALIDATOR.load(deps.storage)?;
    validator.parse_candidates_root_block(boc.as_slice())?;
    VALIDATOR.save(deps.storage, &validator)?;
    Ok(Response::new().add_attributes(vec![("action", "parse_candidates_root_block")]))
}

pub fn init_validators(deps: DepsMut, sender: &Addr) -> Result<Response, ContractError> {
    let mut validator = Validator::default();
    validator.init_validators(deps, sender)?;
    Ok(Response::new().add_attributes(vec![("action", "init_validators")]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::GetCandidatesForValidators {} => to_binary(&get_candidates_for_validators(deps)?),
        QueryMsg::GetValidators {} => to_binary(&get_validators(deps)?),
    }
}

pub fn get_config(deps: Deps) -> StdResult<ConfigResponse> {
    let owner = OWNER.query_admin(deps)?;
    Ok(ConfigResponse { owner: owner.admin })
}

pub fn get_candidates_for_validators(deps: Deps) -> StdResult<Vec<UserFriendlyValidator>> {
    let validator = VALIDATOR.load(deps.storage)?;
    let result = validator.get_candidates_for_validators();
    Ok(result
        .map(|candidate| validator.parse_user_friendly_validator(candidate))
        .to_vec())
}

pub fn get_validators(deps: Deps) -> StdResult<Vec<UserFriendlyValidator>> {
    let validator = VALIDATOR.load(deps.storage)?;
    let result = validator.get_validators();
    Ok(result
        .map(|candidate| validator.parse_user_friendly_validator(candidate))
        .to_vec())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
