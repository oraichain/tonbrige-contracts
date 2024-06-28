use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    attr, Addr, Api, Attribute, CosmosMsg, Decimal, DepsMut, Env, HexBinary, QuerierWrapper,
    Response, StdError, StdResult, Storage, Uint128,
};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw20_ics20_msg::{
    amount::{convert_local_to_remote, convert_remote_to_local, Amount},
    helper::{denom_to_asset_info, parse_asset_info_denom},
};
use oraiswap::{
    asset::{Asset, AssetInfo},
    router::{RouterController, SwapOperation},
};
use std::ops::Mul;
use tonbridge_bridge::{
    msg::{BridgeToTonMsg, FeeData},
    parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id},
    state::{MappingMetadata, PacketReceive, Ratio, SendPacket, Status},
};
use tonbridge_parser::{
    to_bytes32,
    transaction_parser::{ITransactionParser, TransactionParser},
    types::BridgePacketData,
    OPCODE_1, OPCODE_2,
};
use tonbridge_validator::wrapper::ValidatorWrapper;
use tonlib::{
    cell::{BagOfCells, Cell},
    responses::MessageType,
};

use crate::{
    channel::{decrease_channel_balance, increase_channel_balance},
    error::ContractError,
    helper::is_expired,
    state::{
        ics20_denoms, CONFIG, LAST_PACKET_SEQ, PACKET_RECEIVE, PROCESSED_TXS, SEND_PACKET,
        TOKEN_FEE,
    },
};

const DEFAULT_TIMEOUT: u64 = 3600; // 3600s

#[cw_serde]
pub struct Bridge {
    pub validator: ValidatorWrapper,
}

impl Bridge {
    pub fn new(validator_contract_addr: Addr) -> Self {
        Self {
            validator: ValidatorWrapper(validator_contract_addr),
        }
    }
}

impl Bridge {
    pub fn read_transaction(
        &self,
        deps: DepsMut,
        env: &Env,
        contract_address: &str,
        tx_proof: &[u8],
        tx_boc: &[u8],
    ) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
        let mut attrs: Vec<Attribute> = vec![];
        let config = CONFIG.load(deps.storage)?;

        let tx_cells = BagOfCells::parse(tx_boc)?;
        let tx_root = tx_cells.single_root()?;
        let transaction = Cell::load_transaction(tx_root, &mut 0, &mut tx_root.parser())?;
        let transaction_hash = to_bytes32(&HexBinary::from(transaction.hash))?;

        let tx_proof_cells = BagOfCells::parse(tx_proof)?;
        let tx_proof_cell_first_ref = tx_proof_cells.single_root()?.reference(0)?;
        let root_hash = tx_proof_cell_first_ref.get_hash(0);

        let is_root_hash_verified = self
            .validator
            .is_verified_block(&deps.querier, HexBinary::from(root_hash))?;

        if !is_root_hash_verified {
            return Err(ContractError::Std(StdError::generic_err(
                "The block root hash of the tx proof is not verified or invalid. Cannot bridge!",
            )));
        }

        let block_extra_cell = tx_proof_cell_first_ref.reference(3)?;
        let block_extra =
            Cell::load_block_extra(block_extra_cell, &mut 0, &mut block_extra_cell.parser())?;
        if block_extra.account_blocks.is_none() {
            return Err(ContractError::Std(StdError::generic_err(
                "Account blocks are empty. This tx proof is broken",
            )));
        }
        let account_blocks = block_extra.account_blocks.unwrap();
        let mut found_matched_tx = false;
        for acc_block in account_blocks.into_iter() {
            let txs = acc_block.1.transactions;
            for (_key, tx) in txs {
                if let Some(tx_cell) = tx.cell {
                    let tx_hash = tx_cell.get_hash(0);
                    if tx_hash.eq(&transaction_hash) {
                        found_matched_tx = true;
                        break;
                    }
                }
            }
            if found_matched_tx {
                break;
            }
        }

        if !found_matched_tx {
            return Err(ContractError::Std(StdError::generic_err(
                "The tx hash is not in the tx proof's tx hashes!",
            )));
        }

        let is_tx_processed = PROCESSED_TXS
            .may_load(deps.storage, &transaction_hash)?
            .unwrap_or(false);

        if is_tx_processed {
            return Err(ContractError::Std(StdError::generic_err(
                "This tx has already been processed",
            )));
        }

        PROCESSED_TXS.save(deps.storage, &transaction_hash, &true)?;
        let tx_parser = TransactionParser::default();

        let storage = deps.storage;
        let api = deps.api;
        let querier = deps.querier;
        for out_msg in transaction.out_msgs.into_values() {
            if out_msg.data.is_none() {
                deps.api.debug("empty out_msg data");
                continue;
            }
            let out_msg = out_msg.data.unwrap();
            if out_msg.info.msg_type != MessageType::ExternalOut as u8 {
                deps.api.debug("msg type is not external out");
                continue;
            }

            if out_msg.body.cell_ref.is_none() {
                deps.api.debug("cell ref is none when reading transaction");
                continue;
            }
            let cell = out_msg.body.cell_ref.unwrap().0;
            if cell.is_none() {
                deps.api.debug("any cell is empty when reading transaction");
            }

            // verify source of tx is bridge adapter contract
            if out_msg.info.src.to_string() != config.bridge_adapter {
                deps.api
                    .debug("this tx is not from bridge_adapter contract");
                continue;
            }

            let cell = cell.unwrap().cell;
            let packet_data = tx_parser.parse_packet_data(&cell)?.to_pretty()?;

            let mapping = ics20_denoms().load(
                storage,
                &get_key_ics20_ibc_denom(
                    &parse_ibc_wasm_port_id(contract_address),
                    &packet_data.src_channel,
                    &packet_data.src_denom,
                ),
            )?;

            let mut res =
                Bridge::handle_packet_receive(env, storage, api, &querier, packet_data, mapping)?;
            cosmos_msgs.append(&mut res.0);
            attrs.append(&mut res.1);
        }
        Ok((cosmos_msgs, attrs))
    }

    pub fn handle_packet_receive(
        env: &Env,
        storage: &mut dyn Storage,
        api: &dyn Api,
        querier: &QuerierWrapper,
        data: BridgePacketData,
        mapping: MappingMetadata,
    ) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
        let config = CONFIG.load(storage)?;

        let mut packet_receive = PacketReceive {
            seq: data.seq,
            timeout: data.timeout,
            src_denom: data.src_denom.clone(),
            src_channel: data.src_channel.clone(),
            amount: data.amount,
            dest_denom: data.dest_denom.clone(),
            dest_channel: data.dest_channel.clone(),
            dest_receiver: data.dest_receiver.clone(),
            orai_address: data.orai_address.clone(),
            status: Status::Success,
        };
        // check  packet timeout
        if is_expired(env, data.timeout) {
            packet_receive.status = Status::Timeout;
            PACKET_RECEIVE.save(storage, packet_receive.seq, &packet_receive)?;
            return Ok((
                vec![],
                vec![
                    attr("action", "bridge_to_cosmos"),
                    attr("status", "timeout"),
                    attr("packet_receive", format!("{:?}", packet_receive)),
                ],
            ));
        }
        // increase first
        increase_channel_balance(storage, &data.src_channel, &data.src_denom, data.amount)?;

        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
        let recipient = api.addr_validate(&data.orai_address)?;

        let to_send = Amount::from_parts(
            parse_asset_info_denom(&mapping.asset_info),
            convert_remote_to_local(
                data.amount,
                mapping.remote_decimals,
                mapping.asset_info_decimals,
            )?,
        );

        let fee_data = Bridge::process_deduct_fee(storage, querier, api, data.src_denom, to_send)?;

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

        let attributes: Vec<Attribute> = vec![
            attr("action", "bridge_to_cosmos"),
            attr("status", "success"),
            attr("packet_receive", format!("{:?}", packet_receive)),
            attr("dest_receiver", recipient.as_str()),
            attr("local_amount", fee_data.deducted_amount.to_string()),
            attr("relayer_fee", fee_data.relayer_fee.amount().to_string()),
            attr("token_fee", fee_data.token_fee.amount().to_string()),
        ];

        // if the fees have consumed all user funds, we send all the fees to our token fee receiver
        if fee_data.deducted_amount.is_zero() {
            return Ok((cosmos_msgs, attributes));
        }

        let msg = Asset {
            info: mapping.asset_info.clone(),
            amount: fee_data.deducted_amount,
        };
        if mapping.opcode == OPCODE_1 {
            let msg = match msg.info {
                AssetInfo::NativeToken { denom: _ } => {
                    return Err(ContractError::Std(StdError::generic_err(
                        "Cannot mint a native token",
                    )))
                }
                AssetInfo::Token { contract_addr } => {
                    Cw20Contract(contract_addr).call(Cw20ExecuteMsg::Mint {
                        recipient: recipient.to_string(),
                        amount: fee_data.deducted_amount,
                    })
                }
            }?;
            cosmos_msgs.push(msg);
        } else if mapping.opcode == OPCODE_2 {
            cosmos_msgs.push(msg.into_msg(None, querier, recipient)?);
        }

        Ok((cosmos_msgs, attributes))
    }

    pub fn handle_bridge_to_ton(
        deps: DepsMut,
        env: Env,
        msg: BridgeToTonMsg,
        amount: Amount,
        _sender: Addr,
    ) -> Result<Response, ContractError> {
        let timeout = msg
            .timeout
            .unwrap_or(env.block.time.seconds() + DEFAULT_TIMEOUT);
        if is_expired(&env, timeout) {
            return Err(ContractError::Expired {});
        }

        let config = CONFIG.load(deps.storage)?;
        let denom_key = get_key_ics20_ibc_denom(
            &parse_ibc_wasm_port_id(env.contract.address.as_str()),
            &msg.local_channel_id,
            &msg.denom,
        );

        let mapping = ics20_denoms().load(deps.storage, &denom_key)?;
        // ensure amount is correct
        if mapping
            .asset_info
            .ne(&amount.into_asset_info(deps.api).unwrap())
        {
            return Err(ContractError::InvalidFund {});
        }

        let fee_data = Bridge::process_deduct_fee(
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

        let remote_amount = convert_local_to_remote(
            fee_data.deducted_amount,
            mapping.remote_decimals,
            mapping.asset_info_decimals,
        )?;
        // try decrease channel balance
        decrease_channel_balance(
            deps.storage,
            &msg.local_channel_id,
            &msg.denom,
            remote_amount,
        )?;

        // store to pending packet transfer

        let last_packet_seq = LAST_PACKET_SEQ.may_load(deps.storage)?.unwrap_or_default() + 1;

        //FIXME: store timeout to send_packet
        SEND_PACKET.save(
            deps.storage,
            last_packet_seq,
            &SendPacket {
                sequence: last_packet_seq,
                to: msg.to.clone(),
                denom: msg.denom.clone(),
                amount: remote_amount,
                crc_src: msg.crc_src,
            },
        )?;
        LAST_PACKET_SEQ.save(deps.storage, &last_packet_seq)?;

        Ok(Response::new()
            .add_messages(cosmos_msgs)
            .add_attributes(vec![
                ("action", "bridge_to_ton"),
                ("dest_receiver", &msg.to),
                ("dest_denom", &msg.denom),
                ("local_amount", &fee_data.deducted_amount.to_string()),
                ("crc_src", &msg.crc_src.to_string()),
                ("relayer_fee", &fee_data.relayer_fee.amount().to_string()),
                ("token_fee", &fee_data.token_fee.amount().to_string()),
                ("timeout", &timeout.to_owned().to_string()),
                ("remote_amount", &remote_amount.to_string()),
                ("seq", &last_packet_seq.to_string()),
            ]))
    }

    pub fn process_deduct_fee(
        storage: &dyn Storage,
        querier: &QuerierWrapper,
        api: &dyn Api,
        remote_token_denom: String,
        local_amount: Amount, // local amount
    ) -> StdResult<FeeData> {
        let local_denom = local_amount.denom();
        let (deducted_amount, token_fee) =
            Bridge::deduct_token_fee(storage, remote_token_denom, local_amount.amount())?;

        let mut fee_data = FeeData {
            deducted_amount,
            token_fee: Amount::from_parts(local_denom.clone(), token_fee),
            relayer_fee: Amount::from_parts(local_denom.clone(), Uint128::zero()),
        };
        // if after token fee, the deducted amount is 0 then we deduct all to token fee
        if deducted_amount.is_zero() {
            fee_data.token_fee = local_amount;
            return Ok(fee_data);
        }

        // simulate for relayer fee
        let ask_asset_info = denom_to_asset_info(api, &local_amount.raw_denom());
        let relayer_fee = Bridge::deduct_relayer_fee(storage, api, querier, ask_asset_info)?;

        fee_data.deducted_amount = deducted_amount.checked_sub(relayer_fee).unwrap_or_default();
        fee_data.relayer_fee = Amount::from_parts(local_denom.clone(), relayer_fee);
        // if the relayer fee makes the final amount 0, then we charge the remaining deducted amount as relayer fee
        if fee_data.deducted_amount.is_zero() {
            fee_data.relayer_fee = Amount::from_parts(local_denom.clone(), deducted_amount);
            return Ok(fee_data);
        }
        Ok(fee_data)
    }

    pub fn deduct_relayer_fee(
        storage: &dyn Storage,
        _api: &dyn Api,
        querier: &QuerierWrapper,
        ask_asset_info: AssetInfo,
    ) -> StdResult<Uint128> {
        let config = CONFIG.load(storage)?;

        // no need to deduct fee if no fee is found in the mapping
        if config.relayer_fee.is_zero() {
            return Ok(Uint128::from(0u64));
        }

        let relayer_fee = Bridge::get_swap_token_amount_out(
            querier,
            config.relayer_fee,
            &config.swap_router_contract,
            ask_asset_info,
            config.relayer_fee_token,
        );

        Ok(relayer_fee)
    }

    pub fn deduct_token_fee(
        storage: &dyn Storage,
        remote_token_denom: String,
        amount: Uint128,
    ) -> StdResult<(Uint128, Uint128)> {
        let token_fee = TOKEN_FEE.may_load(storage, &remote_token_denom)?;
        if let Some(token_fee) = token_fee {
            let fee = Bridge::deduct_fee(token_fee, amount);
            let new_deducted_amount = amount.checked_sub(fee)?;
            return Ok((new_deducted_amount, fee));
        }
        Ok((amount, Uint128::from(0u64)))
    }

    pub fn deduct_fee(token_fee: Ratio, amount: Uint128) -> Uint128 {
        // ignore case where denominator is zero since we cannot divide with 0
        if token_fee.denominator == 0 {
            return Uint128::from(0u64);
        }

        amount.mul(Decimal::from_ratio(
            token_fee.nominator,
            token_fee.denominator,
        ))
    }

    pub fn get_swap_token_amount_out(
        querier: &QuerierWrapper,
        offer_amount: Uint128,
        swap_router_contract: &RouterController,
        ask_asset_info: AssetInfo,
        relayer_fee_token: AssetInfo,
    ) -> Uint128 {
        if ask_asset_info.eq(&relayer_fee_token) {
            return offer_amount;
        }

        let orai_asset = AssetInfo::NativeToken {
            denom: "orai".to_string(),
        };

        let swap_ops = if ask_asset_info.eq(&orai_asset) || relayer_fee_token.eq(&orai_asset) {
            vec![SwapOperation::OraiSwap {
                offer_asset_info: relayer_fee_token,
                ask_asset_info,
            }]
        } else {
            vec![
                SwapOperation::OraiSwap {
                    offer_asset_info: relayer_fee_token,
                    ask_asset_info: orai_asset.clone(),
                },
                SwapOperation::OraiSwap {
                    offer_asset_info: orai_asset,
                    ask_asset_info,
                },
            ]
        };

        swap_router_contract
            .simulate_swap(querier, offer_amount, swap_ops)
            .map(|data| data.amount)
            .unwrap_or_default()
    }
}
