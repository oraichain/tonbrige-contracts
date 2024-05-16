use cosmwasm_std::{entry_point, to_binary};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use tonbridge_adapter::adapter::Adapter;
use tonbridge_bridge::msg::{ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use tonbridge_parser::bit_reader::to_bytes32;

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
    tx_boc: HexBinary,
    block_boc: HexBinary,
    opcode: HexBinary,
    ton_token: String,
    validator_contract_addr: String,
) -> Result<Response, ContractError> {
    let adapter = Adapter::new(deps.api.addr_validate(&ton_token)?);
    let bridge = Bridge::new(deps.api.addr_validate(&validator_contract_addr)?);
    let cosmos_msgs = bridge.read_transaction(
        deps,
        tx_boc.as_slice(),
        block_boc.as_slice(),
        &adapter,
        to_bytes32(&opcode)?,
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

pub fn is_tx_processed(deps: Deps, tx_hash: HexBinary) -> StdResult<bool> {
    PROCESSED_TXS
        .may_load(deps.storage, &to_bytes32(&tx_hash)?)
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
