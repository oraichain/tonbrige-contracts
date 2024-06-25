use cosmwasm_std::{entry_point, from_binary, to_binary, Addr, Empty, Order, StdError, Uint128};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use cw20::Cw20ReceiveMsg;
use cw20_ics20_msg::amount::Amount;
use cw_utils::{nonpayable, one_coin};
use oraiswap::asset::AssetInfo;
use oraiswap::router::RouterController;
use tonbridge_bridge::msg::{
    BridgeToTonMsg, ChannelResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, MigrateMsg,
    QueryMsg, UpdatePairMsg,
};
use tonbridge_bridge::parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id};
use tonbridge_bridge::state::{Config, MappingMetadata, SendPacket, TokenFee};
use tonbridge_parser::to_bytes32;
use tonlib::cell::Cell;

use crate::bridge::Bridge;
use crate::error::ContractError;
use crate::state::{
    ics20_denoms, CONFIG, OWNER, PROCESSED_TXS, REMOTE_INITIATED_CHANNEL_STATE, SEND_PACKET,
    TOKEN_FEE,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    CONFIG.save(
        deps.storage,
        &Config {
            validator_contract_addr: msg.validator_contract_addr,
            bridge_adapter: msg.bridge_adapter,
            relayer_fee_token: msg.relayer_fee_token,
            token_fee_receiver: msg.token_fee_receiver,
            relayer_fee_receiver: msg.relayer_fee_receiver,
            relayer_fee: msg.relayer_fee.unwrap_or_default(),
            swap_router_contract: RouterController(msg.swap_router_contract),
        },
    )?;
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
        ExecuteMsg::UpdateOwner { new_owner } => execute_update_owner(deps, info, new_owner),
        ExecuteMsg::UpdateConfig {
            validator_contract_addr,
            bridge_adapter,
            relayer_fee_token,
            token_fee_receiver,
            relayer_fee_receiver,
            relayer_fee,
            swap_router_contract,
            token_fee,
        } => execute_update_config(
            deps,
            info,
            validator_contract_addr,
            bridge_adapter,
            relayer_fee_token,
            token_fee_receiver,
            relayer_fee_receiver,
            relayer_fee,
            swap_router_contract,
            token_fee,
        ),
        ExecuteMsg::ReadTransaction { tx_proof, tx_boc } => {
            read_transaction(deps, env, tx_proof, tx_boc)
        }
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

pub fn execute_update_owner(
    deps: DepsMut,
    info: MessageInfo,
    new_owner: Addr,
) -> Result<Response, ContractError> {
    OWNER
        .execute_update_admin::<Empty, Empty>(deps, info, Some(new_owner.clone()))
        .map_err(|error| StdError::generic_err(error.to_string()))?;

    Ok(Response::new().add_attributes(vec![
        ("action", "update_owner"),
        ("new_owner", new_owner.as_str()),
    ]))
}

pub fn execute_update_config(
    deps: DepsMut,
    info: MessageInfo,
    validator_contract_addr: Option<Addr>,
    bridge_adapter: Option<String>,
    relayer_fee_token: Option<AssetInfo>,
    token_fee_receiver: Option<Addr>,
    relayer_fee_receiver: Option<Addr>,
    relayer_fee: Option<Uint128>,
    swap_router_contract: Option<String>,
    token_fee: Option<Vec<TokenFee>>,
) -> Result<Response, ContractError> {
    OWNER.assert_admin(deps.as_ref(), &info.sender)?;

    if let Some(token_fee) = token_fee {
        for fee in token_fee {
            TOKEN_FEE.save(deps.storage, &fee.token_denom, &fee.ratio)?;
        }
    }

    let mut config = CONFIG.load(deps.storage)?;

    if let Some(validator_contract_addr) = validator_contract_addr {
        config.validator_contract_addr = validator_contract_addr;
    }
    if let Some(bridge_adapter) = bridge_adapter {
        config.bridge_adapter = bridge_adapter;
    }
    if let Some(relayer_fee_token) = relayer_fee_token {
        config.relayer_fee_token = relayer_fee_token;
    }
    if let Some(token_fee_receiver) = token_fee_receiver {
        config.token_fee_receiver = token_fee_receiver;
    }
    if let Some(relayer_fee_receiver) = relayer_fee_receiver {
        config.relayer_fee_receiver = relayer_fee_receiver;
    }
    if let Some(relayer_fee) = relayer_fee {
        config.relayer_fee = relayer_fee;
    }
    if let Some(swap_router_contract) = swap_router_contract {
        config.swap_router_contract = RouterController(swap_router_contract);
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default().add_attribute("action", "update_config"))
}

pub fn read_transaction(
    deps: DepsMut,
    env: Env,
    tx_proof: HexBinary,
    tx_boc: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let bridge = Bridge::new(config.validator_contract_addr);
    let res = bridge.read_transaction(
        deps,
        env.contract.address.as_str(),
        tx_proof.as_slice(),
        tx_boc.as_slice(),
    )?;
    Ok(Response::new()
        .add_messages(res.0)
        .add_attributes(vec![("action", "read_transaction")])
        .add_attributes(res.1))
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
            opcode: to_bytes32(&msg.opcode)?,
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
    let mut cell = Cell::default();
    cell.data = boc.as_slice().to_vec();
    cell.bit_len = cell.data.len() * 8;

    let mut parser = cell.parser();

    let seq = parser.load_u64(64)?;
    let to = parser.load_address()?;
    let denom = parser.load_address()?;
    let amount = u128::from_be_bytes(parser.load_bytes(16)?.as_slice().try_into()?);
    let crc_src = parser.load_u32(32)?;

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

    // after finished verifying the boc, we remove the packet to prevent replay attack
    SEND_PACKET.remove(deps.storage, seq);

    Ok(Response::new()
        .add_attribute("action", "submit_bridge_to_ton_info")
        .add_attribute("data", boc.to_hex()))
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
