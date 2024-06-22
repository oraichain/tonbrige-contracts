use cosmwasm_std::{entry_point, from_binary, to_binary, Addr, Order, StdError, Uint128};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use cw20::Cw20ReceiveMsg;
use cw20_ics20_msg::amount::Amount;
use cw_utils::{nonpayable, one_coin};
use tonbridge_bridge::msg::{
    BridgeToTonMsg, ChannelResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg,
    QueryMsg, UpdatePairMsg,
};
use tonbridge_bridge::parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id};
use tonbridge_bridge::state::MappingMetadata;
use tonbridge_parser::bit_reader::to_bytes32;
use tonlib::cell::Cell;

use crate::bridge::Bridge;
use crate::error::ContractError;
use crate::state::{
    ics20_denoms, SendPacket, OWNER, PROCESSED_TXS, REMOTE_INITIATED_CHANNEL_STATE, SEND_PACKET,
};

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
            tx_proof,
            tx_boc,
            opcode,
            validator_contract_addr,
        } => read_transaction(deps, env, tx_proof, tx_boc, opcode, validator_contract_addr),
        ExecuteMsg::UpdateMappingPair(msg) => update_mapping_pair(deps, env, &info.sender, msg),
        ExecuteMsg::BridgeToTon(msg) => {
            let coin = one_coin(&info)?;
            let amount = Amount::from_parts(coin.denom, coin.amount);
            Bridge::handle_bridge_to_ton(deps, env, msg, amount, info.sender)
        }
        ExecuteMsg::Receive(msg) => execute_receive(deps, env, info, msg),
        ExecuteMsg::SubmitBridgeToTonInfo { data } => execute_submit_bridge_to_ton_info(deps, data),
    }
}

pub fn read_transaction(
    deps: DepsMut,
    env: Env,
    tx_proof: HexBinary,
    tx_boc: HexBinary,
    opcode: HexBinary,
    validator_contract_addr: String,
) -> Result<Response, ContractError> {
    let bridge = Bridge::new(deps.api.addr_validate(&validator_contract_addr)?);
    let cosmos_msgs = bridge.read_transaction(
        deps,
        env.contract.address.as_str(),
        tx_proof.as_slice(),
        tx_boc.as_slice(),
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

pub fn execute_receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    wrapper: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let amount = Amount::cw20(wrapper.amount, info.sender);
    let msg: BridgeToTonMsg = from_binary(&wrapper.msg)?;
    let sender = deps.api.addr_validate(&wrapper.sender)?;
    Bridge::handle_bridge_to_ton(deps, env, msg, amount, sender)
}

pub fn execute_submit_bridge_to_ton_info(
    deps: DepsMut,
    boc: HexBinary,
) -> Result<Response, ContractError> {
    // seq: 64 bit
    // address:

    let mut cell = Cell::default();
    cell.data = boc.as_slice().to_vec();
    cell.bit_len = cell.data.len() * 8;

    let mut parsers = cell.parser();

    let seq = parsers.load_u64(64)?;
    let to = parsers.load_address()?;
    let denom = parsers.load_address()?;
    let amount = u128::from_be_bytes(parsers.load_bits(128)?.as_slice().try_into().unwrap());
    let crc_src = parsers.load_u32(32)?;

    println!(
        "{:?}",
        (&SendPacket {
            sequence: seq,
            to: to.to_string(),
            denom: denom.to_string(),
            amount: Uint128::from(amount),
            crc_src,
        })
    );

    let send_packet = SEND_PACKET.load(deps.storage, seq)?;
    if send_packet.ne(&SendPacket {
        sequence: seq,
        to: to.to_string(),
        denom: denom.to_string(),
        amount: Uint128::from(amount),
        crc_src,
    }) {
        return Err(ContractError::Std(StdError::generic_err(
            "Invalid send_packet",
        )));
    }

    Ok(Response::new()
        .add_attribute("action", "submit_bridge_to_ton_info")
        .add_attribute("data", boc.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::IsTxProcessed { tx_hash } => to_binary(&is_tx_processed(deps, tx_hash)?),
        QueryMsg::ChannelStateData { channel_id } => to_binary(&query_channel(deps, channel_id)?),
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

// make public for ibc tests
pub fn query_channel(deps: Deps, channel_id: String) -> StdResult<ChannelResponse> {
    let state = REMOTE_INITIATED_CHANNEL_STATE
        .prefix(&channel_id)
        .range(deps.storage, None, None, Order::Ascending)
        .map(|r| {
            // this denom is
            r.map(|(denom, v)| {
                let outstanding = Amount::from_parts(denom.clone(), v.outstanding);
                let total = Amount::from_parts(denom, v.total_sent);
                (outstanding, total)
            })
        })
        .collect::<StdResult<Vec<_>>>()?;
    // we want (Vec<outstanding>, Vec<total>)
    let (balances, total_sent): (Vec<Amount>, Vec<Amount>) = state.into_iter().unzip();

    Ok(ChannelResponse {
        balances,
        total_sent,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
