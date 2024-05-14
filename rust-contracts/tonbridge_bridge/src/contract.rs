use cosmwasm_std::{entry_point, to_binary};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw_tonbridge_adapter::adapter::Adapter;
use tonbridge_bridge::msg::{ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use tonbridge_parser::types::Bytes32;

use crate::bridge::Bridge;
use crate::error::ContractError;
use crate::state::{OWNER, PROCESSED_TXS};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ReadTransaction {
            tx_boc,
            block_boc,
            opcode,
            ton_token,
            validator_contract_addr,
        } => read_transaction(
            deps,
            tx_boc,
            block_boc,
            opcode,
            ton_token,
            validator_contract_addr,
        ),
    }
}

pub fn read_transaction(
    deps: DepsMut,
    tx_boc: String,
    block_boc: String,
    opcode: String,
    ton_token: String,
    validator_contract_addr: String,
) -> Result<Response, ContractError> {
    let adapter = Adapter::new(deps.api.addr_validate(&ton_token)?);
    let bridge = Bridge::new(deps.api.addr_validate(&validator_contract_addr)?);
    let mut opcode_bytes = Bytes32::default();
    opcode_bytes.copy_from_slice(opcode.as_bytes());
    let cosmos_msgs = bridge.read_transaction(
        deps,
        tx_boc.as_bytes(),
        block_boc.as_bytes(),
        &adapter,
        opcode_bytes,
    )?;
    Ok(Response::new()
        .add_messages(cosmos_msgs)
        .add_attributes(vec![("action", "read_transaction")]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::IsTxProcessed { tx_hash } => to_binary(&is_tx_processed(deps, tx_hash)?),
    }
}

pub fn is_tx_processed(deps: Deps, tx_hash: String) -> StdResult<bool> {
    let mut tx_hash_bytes = Bytes32::default();
    tx_hash_bytes.copy_from_slice(tx_hash.as_bytes());
    PROCESSED_TXS
        .may_load(deps.storage, &tx_hash_bytes)
        .map(|res| res.unwrap_or(false))
}

pub fn get_config(deps: Deps) -> StdResult<ConfigResponse> {
    let owner = OWNER.query_admin(deps)?;
    Ok(ConfigResponse { owner: owner.admin })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
