use cosmwasm_std::{
    attr, Addr, Api, Attribute, CosmosMsg, DepsMut, Env, HexBinary, QuerierWrapper, Response,
    Storage, Uint256,
};

use oraiswap::asset::Asset;
use tonbridge_bridge::{
    amount::{convert_local_to_remote, convert_remote_to_local, Amount},
    msg::BridgeToTonMsg,
    state::{MappingMetadata, TimeoutSendPacket},
};
use tonbridge_parser::{
    transaction_parser::{
        ITransactionParser, TransactionParser, RECEIVE_PACKET_MAGIC_NUMBER,
        SEND_TO_TON_MAGIC_NUMBER,
    },
    types::{BridgePacketData, Status},
    OPCODE_1, OPCODE_2,
};
use tonlib::cell::Cell;

use crate::{
    bridge::Bridge,
    channel::{decrease_channel_balance, increase_channel_balance},
    error::ContractError,
    fee::process_deduct_fee,
    helper::{
        build_ack_commitment, build_bridge_to_ton_commitment, build_burn_asset_msg,
        build_mint_asset_msg, is_expired, parse_asset_info_denom,
    },
    state::{
        ics20_denoms, ACK_COMMITMENT, CONFIG, LAST_PACKET_SEQ, SEND_PACKET, SEND_PACKET_COMMITMENT,
    },
};

pub const DEFAULT_TIMEOUT: u64 = 3600; // 3600s

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

    for out_msg in transaction.out_msgs.into_values() {
        let cell = Bridge::validate_transaction_out_msg(out_msg, config.bridge_adapter.clone());

        if cell.is_none() {
            continue;
        }
        let cell = cell.unwrap();

        // check type of transaction: packetReceive or ack
        let op_code = cell.parser().load_u32(32)?;
        match op_code {
            // ack
            SEND_TO_TON_MAGIC_NUMBER => {
                let mut res = on_acknowledgment(deps, &cell)?;
                cosmos_msgs.append(&mut res.0);
                attrs.append(&mut res.1);
            }
            // on receive packet
            RECEIVE_PACKET_MAGIC_NUMBER => {
                let mut res = on_packet_receive(deps, env, &cell)?;
                cosmos_msgs.append(&mut res.0);
                attrs.append(&mut res.1);
            }

            _ => continue,
        }
        // we assume that one transaction only has one matching external out msg. After handling it -> we stop reading
        break;
    }
    Ok(Response::new()
        .add_attributes(attrs)
        .add_messages(cosmos_msgs))
}

fn on_packet_receive(
    deps: DepsMut,
    env: Env,
    cell: &Cell,
) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
    let tx_parser = TransactionParser::default();
    let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
    let mut attrs: Vec<Attribute> = vec![attr("action", "send_to_cosmos")];

    let packet_data = tx_parser.parse_packet_data(cell)?.to_pretty()?;

    let mapping = ics20_denoms().load(deps.storage, &packet_data.src_denom)?;

    let mut res = handle_packet_receive(
        deps.storage,
        deps.api,
        &deps.querier,
        env.block.time.seconds(),
        packet_data,
        mapping,
    )?;
    cosmos_msgs.append(&mut res.0);
    attrs.append(&mut res.1);

    Ok((cosmos_msgs, attrs))
}

pub fn on_acknowledgment(
    deps: DepsMut,
    cell: &Cell,
) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
    let tx_parser = TransactionParser::default();
    let mut msgs: Vec<CosmosMsg> = vec![];
    let mut attrs: Vec<Attribute> = vec![attr("action", "acknowledgment")];

    let ack = tx_parser.parse_ack_data(cell)?;

    // if not success, try refunds
    if ack.status.ne(&Status::Success) {
        let send_packet = SEND_PACKET.load(deps.storage, ack.seq)?;

        if send_packet.opcode == OPCODE_1 {
            let config = CONFIG.load(deps.storage)?;
            msgs.push(build_mint_asset_msg(
                config.token_factory_addr,
                &send_packet.local_refund_asset,
                send_packet.sender,
            )?);
        } else {
            msgs.push(send_packet.local_refund_asset.into_msg(
                None,
                &deps.querier,
                deps.api.addr_validate(&send_packet.sender)?,
            )?);
        }
    }

    SEND_PACKET_COMMITMENT.remove(deps.storage, ack.seq);
    SEND_PACKET.remove(deps.storage, ack.seq);
    attrs.push(attr("seq", ack.seq.to_string()));
    attrs.push(attr("status", ack.status.to_string()));

    Ok((msgs, attrs))
}

pub fn handle_packet_receive(
    storage: &mut dyn Storage,
    api: &dyn Api,
    querier: &QuerierWrapper,
    current_timestamp: u64,
    data: BridgePacketData,
    mapping: MappingMetadata,
) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
    // check unique sequence
    if ACK_COMMITMENT.may_load(storage, data.seq)?.is_some() {
        return Err(ContractError::ReceiveSeqDuplicated {});
    }

    let config = CONFIG.load(storage)?;

    let recipient = api.addr_humanize(&data.receiver)?;

    let mut attrs: Vec<Attribute> = vec![
        attr("seq", data.seq.to_string()),
        attr("opcode_packet", RECEIVE_PACKET_MAGIC_NUMBER.to_string()),
        attr("remote_amount", data.amount),
        attr("timeout_timestamp", data.timeout_timestamp.to_string()),
        attr("recipient", recipient.as_str()),
        attr("remote_denom", data.src_denom.clone()),
        attr("remote_sender", data.src_sender.clone()),
    ];

    // check packet timeout
    if is_expired(current_timestamp, data.timeout_timestamp) {
        // must store timeout commitment
        let commitment = build_ack_commitment(
            data.seq,
            data.token_origin,
            data.amount,
            data.timeout_timestamp,
            data.receiver.as_slice(),
            &data.src_denom,
            &data.src_sender,
            Status::Timeout,
        )?;
        ACK_COMMITMENT.save(
            storage,
            data.seq,
            &Uint256::from_be_bytes(commitment.as_slice().try_into()?),
        )?;
        attrs.push(attr("ack", (Status::Timeout as u8).to_string()));
        attrs.push(attr("ack_value", "timeout"));

        return Ok((vec![], attrs));
    }

    // increase first
    increase_channel_balance(storage, &data.src_denom, data.amount)?;

    let mut cosmos_msgs: Vec<CosmosMsg> = vec![];

    let to_send = Amount::from_parts(
        parse_asset_info_denom(&mapping.asset_info),
        convert_remote_to_local(
            data.amount,
            mapping.remote_decimals,
            mapping.asset_info_decimals,
        )?,
    );

    let fee_data = process_deduct_fee(storage, querier, api, data.src_denom.clone(), to_send)?;
    let local_amount = fee_data.deducted_amount;

    if !fee_data.token_fee.is_empty() {
        cosmos_msgs.push(
            fee_data
                .token_fee
                .send_amount(config.token_fee_receiver.into_string(), None),
        )
    }
    if !fee_data.relayer_fee.is_empty() {
        cosmos_msgs.push(
            fee_data
                .relayer_fee
                .send_amount(config.relayer_fee_receiver.to_string(), None),
        )
    }

    attrs.append(&mut vec![
        attr("ack", (Status::Success as u8).to_string()),
        attr("ack_value", "success"),
        attr("local_amount", local_amount.to_string()),
        attr("relayer_fee", fee_data.relayer_fee.amount().to_string()),
        attr("token_fee", fee_data.token_fee.amount().to_string()),
    ]);

    // if the fees have consumed all user funds, we send all the fees to our token fee receiver
    if local_amount.is_zero() {
        return Ok((cosmos_msgs, attrs));
    }

    let msg = Asset {
        info: mapping.asset_info.clone(),
        amount: local_amount,
    };
    if mapping.opcode == OPCODE_1 {
        cosmos_msgs.push(build_mint_asset_msg(
            config.token_factory_addr,
            &msg,
            recipient.to_string(),
        )?);
    } else {
        cosmos_msgs.push(msg.into_msg(None, querier, recipient.clone())?);
    }

    // store ack commitment
    let commitment = build_ack_commitment(
        data.seq,
        data.token_origin,
        data.amount,
        data.timeout_timestamp,
        data.receiver.as_slice(),
        &data.src_denom,
        &data.src_sender,
        Status::Success,
    )?;
    ACK_COMMITMENT.save(
        storage,
        data.seq,
        &Uint256::from_be_bytes(commitment.as_slice().try_into()?),
    )?;

    Ok((cosmos_msgs, attrs))
}

pub fn handle_bridge_to_ton(
    deps: DepsMut,
    env: Env,
    msg: BridgeToTonMsg,
    amount: Amount,
    sender: Addr,
) -> Result<Response, ContractError> {
    let timeout_timestamp = msg
        .timeout
        .unwrap_or(env.block.time.seconds() + DEFAULT_TIMEOUT);

    let config = CONFIG.load(deps.storage)?;

    let mapping = ics20_denoms().load(deps.storage, &msg.denom)?;
    // ensure amount is correct
    if mapping
        .asset_info
        .ne(&amount.into_asset_info(deps.api).unwrap())
    {
        return Err(ContractError::InvalidFund {});
    }

    let fee_data = process_deduct_fee(
        deps.storage,
        &deps.querier,
        deps.api,
        msg.denom.clone(),
        amount.clone(),
    )?;

    let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
    if !fee_data.token_fee.is_empty() {
        cosmos_msgs.push(
            fee_data
                .token_fee
                .send_amount(config.token_fee_receiver.into_string(), None),
        )
    }
    if !fee_data.relayer_fee.is_empty() {
        cosmos_msgs.push(
            fee_data
                .relayer_fee
                .send_amount(config.relayer_fee_receiver.into_string(), None),
        )
    }

    let local_amount = fee_data.deducted_amount;
    let remote_amount = convert_local_to_remote(
        local_amount,
        mapping.remote_decimals,
        mapping.asset_info_decimals,
    )?;
    // try decrease channel balance
    decrease_channel_balance(deps.storage, &msg.denom, remote_amount)?;

    if mapping.opcode == OPCODE_1 {
        cosmos_msgs.push(build_burn_asset_msg(
            config.token_factory_addr,
            &Asset {
                info: mapping.asset_info.clone(),
                amount: local_amount,
            },
            env.contract.address.to_string(),
        )?);
    }

    let last_packet_seq = LAST_PACKET_SEQ.may_load(deps.storage)?.unwrap_or_default() + 1;

    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let commitment = build_bridge_to_ton_commitment(
        last_packet_seq,
        mapping.token_origin,
        sender_raw.as_slice(),
        &msg.to,
        &msg.denom,
        remote_amount,
        timeout_timestamp,
    )?;

    SEND_PACKET_COMMITMENT.save(
        deps.storage,
        last_packet_seq,
        &Uint256::from_be_bytes(commitment.as_slice().try_into()?),
    )?;

    // this packet is saved just in case we need to refund the sender due to timeout
    SEND_PACKET.save(
        deps.storage,
        last_packet_seq,
        &TimeoutSendPacket {
            sender: sender.to_string(),
            local_refund_asset: Asset {
                info: mapping.asset_info,
                amount: local_amount,
            },
            timeout_timestamp,
            opcode: mapping.opcode,
        },
    )?;
    LAST_PACKET_SEQ.save(deps.storage, &last_packet_seq)?;

    Ok(Response::new()
        .add_messages(cosmos_msgs)
        .add_attributes(vec![
            ("action", "send_to_ton"),
            ("opcode_packet", &SEND_TO_TON_MAGIC_NUMBER.to_string()),
            ("local_sender", sender.as_str()),
            ("remote_receiver", &msg.to),
            ("remote_denom", &msg.denom),
            ("local_amount", &local_amount.to_string()),
            ("token_origin", &mapping.token_origin.to_string()),
            ("relayer_fee", &fee_data.relayer_fee.amount().to_string()),
            ("token_fee", &fee_data.token_fee.amount().to_string()),
            (
                "timeout_timestamp",
                &timeout_timestamp.to_owned().to_string(),
            ),
            ("remote_amount", &remote_amount.to_string()),
            ("seq", &last_packet_seq.to_string()),
        ]))
}
