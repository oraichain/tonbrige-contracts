use cosmwasm_std::{entry_point, to_binary, Addr};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use tonbridge_bridge::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg, UpdatePairMsg,
};
use tonbridge_bridge::state::MappingMetadata;
use tonbridge_bridge::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id};
use tonbridge_parser::bit_reader::to_bytes32;

use crate::bridge::Bridge;
use crate::error::ContractError;
use crate::state::{ics20_denoms, OWNER, PROCESSED_TXS};

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
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ReadTransaction {
            tx_boc,
            block_boc,
            opcode,
            validator_contract_addr,
        } => read_transaction(
            deps,
            env,
            tx_boc,
            block_boc,
            opcode,
            validator_contract_addr,
        ),
        ExecuteMsg::UpdateMappingPair(msg) => update_mapping_pair(deps, env, &info.sender, msg),
    }
}

pub fn read_transaction(
    deps: DepsMut,
    env: Env,
    tx_boc: HexBinary,
    block_boc: HexBinary,
    opcode: HexBinary,
    validator_contract_addr: String,
) -> Result<Response, ContractError> {
    let bridge = Bridge::new(deps.api.addr_validate(&validator_contract_addr)?);
    let cosmos_msgs = bridge.read_transaction(
        deps,
        env.contract.address.as_str(),
        tx_boc.as_slice(),
        block_boc.as_slice(),
        to_bytes32(&opcode)?,
    )?;
    Ok(Response::new()
        .add_messages(cosmos_msgs)
        .add_attributes(vec![("action", "read_transaction")]))
}

pub fn update_mapping_pair(
    deps: DepsMut,
    env: Env,
    caller: &Addr,
    msg: UpdatePairMsg,
) -> Result<Response, ContractError> {
    OWNER.assert_admin(deps.as_ref(), caller)?;
    let ibc_denom = get_key_ics20_ibc_denom(
        &parse_ibc_wasm_port_id(env.contract.address.as_str()),
        &msg.local_channel_id,
        &msg.denom,
    );

    // if pair already exists in list, remove it and create a new one
    if ics20_denoms().load(deps.storage, &ibc_denom).is_ok() {
        ics20_denoms().remove(deps.storage, &ibc_denom)?;
    }

    ics20_denoms().save(
        deps.storage,
        &ibc_denom,
        &MappingMetadata {
            asset_info: msg.local_asset_info.clone(),
            remote_decimals: msg.remote_decimals,
            asset_info_decimals: msg.local_asset_info_decimals,
        },
    )?;
    Ok(Response::new().add_attributes(vec![("action", "update_mapping_pair")]))
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
