#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, from_binary, to_binary, Addr, Api, Attribute, CosmosMsg, Empty, Order, QuerierWrapper,
    StdError, Storage, Uint128,
};
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use cw20::Cw20ReceiveMsg;
use cw20_ics20_msg::amount::Amount;
use cw_utils::{nonpayable, one_coin};
use oraiswap::asset::AssetInfo;
use oraiswap::router::RouterController;
use tonbridge_bridge::msg::{
    BridgeToTonMsg, ChannelResponse, DeletePairMsg, ExecuteMsg, InstantiateMsg, MigrateMsg,
    PairQuery, QueryMsg, UpdatePairMsg,
};

use tonbridge_bridge::state::{Config, MappingMetadata, TokenFee};
use tonbridge_parser::to_bytes32;
use tonbridge_parser::transaction_parser::{ITransactionParser, TransactionParser};
use tonlib::cell::{BagOfCells, Cell};
use tonlib::responses::{MaybeRefData, TransactionMessage};

use crate::bridge::Bridge;
use crate::error::ContractError;
use crate::helper::is_expired;
use crate::state::{
    ics20_denoms, CONFIG, OWNER, PROCESSED_TXS, REMOTE_INITIATED_CHANNEL_STATE,
    SEND_PACKET_COMMITMENT, TIMEOUT_SEND_PACKET, TOKEN_FEE,
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
        ExecuteMsg::UpdateMappingPair(msg) => update_mapping_pair(deps, &info.sender, msg),
        ExecuteMsg::DeleteMappingPair(msg) => execute_delete_mapping_pair(deps, info, msg),
        ExecuteMsg::BridgeToTon(msg) => {
            let coin = one_coin(&info)?;
            let amount = Amount::from_parts(coin.denom, coin.amount);
            Bridge::handle_bridge_to_ton(deps, env, msg, amount, info.sender)
        }
        ExecuteMsg::Receive(msg) => execute_receive(deps, env, info, msg),
        ExecuteMsg::ProcessTimeoutSendPacket {
            masterchain_header_proof,
            tx_boc,
            tx_proof_unreceived,
        } => {
            process_timeout_send_packet(deps, masterchain_header_proof, tx_proof_unreceived, tx_boc)
        }
        ExecuteMsg::Acknowledgment { tx_proof, tx_boc } => acknowledgment(deps, tx_proof, tx_boc),
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

#[allow(clippy::too_many_arguments)]
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
    let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
    let mut attrs: Vec<Attribute> = vec![];
    let transaction = bridge.read_transaction(
        deps.storage,
        &deps.querier,
        tx_proof.as_slice(),
        tx_boc.as_slice(),
    )?;
    let tx_parser = TransactionParser::default();
    for out_msg in transaction.out_msgs.into_values() {
        let cell = Bridge::validate_transaction_out_msg(out_msg, config.bridge_adapter.clone());

        if cell.is_none() {
            continue;
        }
        let cell = cell.unwrap();
        let packet_data = tx_parser.parse_packet_data(&cell)?.to_pretty()?;

        let mapping = ics20_denoms().load(deps.storage, &packet_data.src_denom)?;

        let mut res = Bridge::handle_packet_receive(
            deps.storage,
            deps.api,
            &deps.querier,
            env.block.time.seconds(),
            packet_data,
            mapping,
        )?;
        cosmos_msgs.append(&mut res.0);
        attrs.append(&mut res.1);

        // we assume that one transaction only has one matching external out msg. After handling it -> we stop reading
        break;
    }
    Ok(Response::new()
        .add_messages(cosmos_msgs)
        .add_attributes(vec![("action", "send_to_cosmos")])
        .add_attributes(attrs))
}

pub fn acknowledgment(
    deps: DepsMut,
    tx_proof: HexBinary,
    tx_boc: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let bridge = Bridge::new(config.validator_contract_addr);

    let mut attrs: Vec<Attribute> = vec![];
    let transaction = bridge.read_transaction(
        deps.storage,
        &deps.querier,
        tx_proof.as_slice(),
        tx_boc.as_slice(),
    )?;
    let tx_parser = TransactionParser::default();
    for out_msg in transaction.out_msgs.into_values() {
        let cell = Bridge::validate_transaction_out_msg(out_msg, config.bridge_adapter.clone());
        if cell.is_none() {
            continue;
        }
        let cell = cell.unwrap();
        let seq = tx_parser.parse_ack_data(&cell)?;

        SEND_PACKET_COMMITMENT.remove(deps.storage, seq);
        attrs.push(attr("seq", &seq.to_string()));
    }
    Ok(Response::new()
        .add_attributes(vec![("action", "acknowledgment")])
        .add_attributes(attrs))
}

pub fn update_mapping_pair(
    deps: DepsMut,
    caller: &Addr,
    msg: UpdatePairMsg,
) -> Result<Response, ContractError> {
    OWNER.assert_admin(deps.as_ref(), caller)?;

    // if pair already exists in list, remove it and create a new one
    if ics20_denoms().load(deps.storage, &msg.denom).is_ok() {
        ics20_denoms().remove(deps.storage, &msg.denom)?;
    }

    ics20_denoms().save(
        deps.storage,
        &msg.denom,
        &MappingMetadata {
            asset_info: msg.local_asset_info.clone(),
            remote_decimals: msg.remote_decimals,
            asset_info_decimals: msg.local_asset_info_decimals,
            opcode: to_bytes32(&msg.opcode)?,
            token_origin: msg.token_origin,
        },
    )?;
    Ok(Response::new().add_attributes(vec![("action", "update_mapping_pair")]))
}

pub fn execute_delete_mapping_pair(
    deps: DepsMut,
    info: MessageInfo,
    mapping_pair_msg: DeletePairMsg,
) -> Result<Response, ContractError> {
    OWNER.assert_admin(deps.as_ref(), &info.sender)?;

    ics20_denoms().remove(deps.storage, &mapping_pair_msg.denom)?;

    let res = Response::new()
        .add_attribute("action", "execute_delete_mapping_pair")
        .add_attribute("original_denom", mapping_pair_msg.denom);
    Ok(res)
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

pub fn process_timeout_send_packet(
    deps: DepsMut,
    latest_masterchain_header_proof: HexBinary,
    tx_proof_unreceived: HexBinary,
    tx_boc: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let bridge = Bridge::new(config.validator_contract_addr);

    let header_cells = BagOfCells::parse_hex(&latest_masterchain_header_proof.to_hex())?;
    let block_cell = header_cells.single_root()?.reference(0)?;

    // TODO: need to update latest client state of TON every time we have a new incoming tx
    // so that we can verify the logical time against the latest_masterchain_header_proof
    let block_info = Cell::load_block(block_cell)?;
    let masterchain_block_latest_timestamp =
        block_info.info.to_owned().unwrap_or_default().gen_utime;

    let transaction = bridge.read_transaction(
        deps.storage,
        &deps.querier,
        tx_proof_unreceived.as_slice(),
        tx_boc.as_slice(),
    )?;

    for out_msg in transaction.out_msgs.into_values() {
        let refund_msgs = build_timeout_send_packet_refund_msgs(
            deps.storage,
            deps.api,
            &deps.querier,
            out_msg,
            config.bridge_adapter.clone(),
            masterchain_block_latest_timestamp,
        )?;
        if refund_msgs.is_empty() {
            continue;
        }

        return Ok(Response::new()
            .add_attribute("action", "process_timeout_send_packet")
            .add_messages(refund_msgs));
    }
    Err(ContractError::Std(StdError::generic_err(
        "The given transaction has no timeout message",
    )))
}

pub fn build_timeout_send_packet_refund_msgs(
    storage: &mut dyn Storage,
    api: &dyn Api,
    querier: &QuerierWrapper,
    out_msg: MaybeRefData<TransactionMessage>,
    bridge_adapter: String,
    latest_masterchain_block_timestamp: u32,
) -> Result<Vec<CosmosMsg>, ContractError> {
    let tx_parser = TransactionParser::default();
    let cell = Bridge::validate_transaction_out_msg(out_msg, bridge_adapter);
    if cell.is_none() {
        return Ok(vec![]);
    }
    let cell = cell.unwrap();
    let packet_seq_timeout = tx_parser.parse_send_packet_timeout_data(&cell)?;

    let timeout_packet = TIMEOUT_SEND_PACKET.may_load(storage, packet_seq_timeout)?;

    // no-op to prevent error spamming from the relayer
    if timeout_packet.is_none() {
        return Ok(vec![]);
    }
    let timeout_packet = timeout_packet.unwrap();
    if !is_expired(
        latest_masterchain_block_timestamp as u64,
        timeout_packet.timeout_timestamp,
    ) {
        return Err(ContractError::NotExpired {});
    }
    let refund_msg = timeout_packet.local_refund_asset.into_msg(
        None,
        querier,
        api.addr_validate(&timeout_packet.sender)?,
    )?;

    TIMEOUT_SEND_PACKET.remove(storage, packet_seq_timeout);
    SEND_PACKET_COMMITMENT.remove(storage, packet_seq_timeout);

    Ok(vec![refund_msg])
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Owner {} => to_binary(&OWNER.query_admin(deps)?.admin),
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::TokenFee { remote_token_denom } => {
            to_binary(&TOKEN_FEE.load(deps.storage, &remote_token_denom)?)
        }
        QueryMsg::IsTxProcessed { tx_hash } => to_binary(&is_tx_processed(deps, tx_hash)?),
        QueryMsg::ChannelStateData {} => to_binary(&query_channel(deps)?),
        QueryMsg::PairMapping { key } => to_binary(&get_mapping_from_key(deps, key)?),
        QueryMsg::SendPacketCommitment { seq } => {
            to_binary(&SEND_PACKET_COMMITMENT.load(deps.storage, seq)?)
        }
    }
}

pub fn is_tx_processed(deps: Deps, tx_hash: HexBinary) -> StdResult<bool> {
    PROCESSED_TXS
        .may_load(deps.storage, &to_bytes32(&tx_hash)?)
        .map(|res| res.unwrap_or(false))
}

pub fn get_config(deps: Deps) -> StdResult<Config> {
    let config = CONFIG.load(deps.storage)?;
    Ok(config)
}

// make public for ibc tests
pub fn query_channel(deps: Deps) -> StdResult<ChannelResponse> {
    let state = REMOTE_INITIATED_CHANNEL_STATE
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

fn get_mapping_from_key(deps: Deps, ibc_denom: String) -> StdResult<PairQuery> {
    let result = ics20_denoms().load(deps.storage, &ibc_denom)?;
    Ok(PairQuery {
        key: ibc_denom,
        pair_mapping: result,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
