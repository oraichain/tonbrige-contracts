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
    state::{MappingMetadata, Ratio, ReceivePacket, SendPacket, TimeoutSendPacket},
};
use tonbridge_parser::{to_bytes32, types::BridgePacketData, OPCODE_1, OPCODE_2};
use tonbridge_validator::wrapper::ValidatorWrapper;
use tonlib::{
    address::TonAddress,
    cell::{BagOfCells, Cell, CellBuilder},
    responses::{MaybeRefData, MessageType, Transaction, TransactionMessage},
};

use crate::{
    channel::{decrease_channel_balance, increase_channel_balance},
    error::ContractError,
    helper::is_expired,
    state::{
        ics20_denoms, CONFIG, LAST_PACKET_SEQ, PROCESSED_TXS, SEND_PACKET, SEND_PACKET_COMMITMENT,
        TIMEOUT_RECEIVE_PACKET, TIMEOUT_RECEIVE_PACKET_COMMITMENT, TIMEOUT_SEND_PACKET, TOKEN_FEE,
    },
};

pub const DEFAULT_TIMEOUT: u64 = 3600; // 3600s
pub const RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER: u32 = 0x64060175; // crc32("recv::timeout_recv_packet")
pub const SEND_TO_TON_MAGIC_NUMBER: u32 = 0x4E545F4; // crc32("src::cosmos")

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
    pub fn validate_transaction_out_msg(
        out_msg: MaybeRefData<TransactionMessage>,
        bridge_adapter_addr: String,
    ) -> Option<Cell> {
        if out_msg.data.is_none() {
            return None;
        }
        let out_msg = out_msg.data.unwrap();
        if out_msg.info.msg_type != MessageType::ExternalOut as u8 {
            return None;
        }
        // verify source of tx is bridge adapter contract
        if out_msg.info.src.to_string() != bridge_adapter_addr {
            return None;
        }

        if out_msg.body.cell_ref.is_none() {
            return None;
        }
        let cell = out_msg.body.cell_ref.unwrap().0;
        if cell.is_none() {
            return None;
        }

        // body cell
        Some(cell.unwrap().cell)
    }

    pub fn read_transaction(
        &self,
        storage: &mut dyn Storage,
        querier: &QuerierWrapper,
        tx_proof: &[u8],
        tx_boc: &[u8],
    ) -> Result<Transaction, ContractError> {
        let tx_cells = BagOfCells::parse(tx_boc)?;
        let tx_root = tx_cells.single_root()?;
        let transaction = Cell::load_transaction(tx_root, &mut 0, &mut tx_root.parser())?;
        let transaction_hash = to_bytes32(&HexBinary::from(transaction.hash.clone()))?;

        let tx_proof_cells = BagOfCells::parse(tx_proof)?;
        let tx_proof_cell_first_ref = tx_proof_cells.single_root()?.reference(0)?;
        let root_hash = tx_proof_cell_first_ref.get_hash(0);

        let is_root_hash_verified = self
            .validator
            .is_verified_block(querier, HexBinary::from(root_hash))?;

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
            .may_load(storage, &transaction_hash)?
            .unwrap_or(false);

        if is_tx_processed {
            return Err(ContractError::Std(StdError::generic_err(
                "This tx has already been processed",
            )));
        }

        PROCESSED_TXS.save(storage, &transaction_hash, &true)?;
        Ok(transaction)
    }

    pub fn handle_packet_receive(
        storage: &mut dyn Storage,
        api: &dyn Api,
        querier: &QuerierWrapper,
        current_timestamp: u64,
        data: BridgePacketData,
        mapping: MappingMetadata,
    ) -> Result<(Vec<CosmosMsg>, Vec<Attribute>), ContractError> {
        let config = CONFIG.load(storage)?;

        let receive_packet: ReceivePacket = ReceivePacket {
            magic: RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER,
            seq: data.seq,
            timeout_timestamp: data.timeout_timestamp,
            src_sender: data.src_sender.clone(),
            src_denom: data.src_denom.clone(),
            src_channel: data.src_channel.clone(),
            amount: data.amount,
        };
        // check packet timeout
        if is_expired(current_timestamp, data.timeout_timestamp) {
            TIMEOUT_RECEIVE_PACKET.save(storage, receive_packet.seq, &receive_packet)?;
            // must store timeout commitment
            let mut cell_builder = CellBuilder::new();
            cell_builder.store_bits(
                32,
                &RECEIVE_PACKET_TIMEOUT_MAGIC_NUMBER.to_be_bytes().to_vec(),
            )?; // opcode
            cell_builder.store_bits(64, &data.seq.to_be_bytes().to_vec())?; // seq
            let commitment: Vec<u8> = cell_builder.build()?.cell_hash()?;
            TIMEOUT_RECEIVE_PACKET_COMMITMENT.save(
                storage,
                receive_packet.seq,
                &to_bytes32(&HexBinary::from(commitment))?,
            )?;

            return Ok((vec![], vec![attr("status", "timeout")]));
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

        let attributes: Vec<Attribute> = vec![
            attr("status", "success"),
            attr("dest_receiver", recipient.as_str()),
            attr("local_amount", local_amount.to_string()),
            attr("relayer_fee", fee_data.relayer_fee.amount().to_string()),
            attr("token_fee", fee_data.token_fee.amount().to_string()),
        ];

        // if the fees have consumed all user funds, we send all the fees to our token fee receiver
        if local_amount.is_zero() {
            return Ok((cosmos_msgs, attributes));
        }

        let msg = Asset {
            info: mapping.asset_info.clone(),
            amount: local_amount,
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
                        amount: local_amount,
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
        sender: Addr,
    ) -> Result<Response, ContractError> {
        let timeout_timestamp = msg
            .timeout
            .unwrap_or(env.block.time.seconds() + DEFAULT_TIMEOUT);

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

        let local_amount = fee_data.deducted_amount;
        let remote_amount = convert_local_to_remote(
            local_amount,
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
        SEND_PACKET.save(
            deps.storage,
            last_packet_seq,
            &SendPacket {
                sequence: last_packet_seq,
                to: msg.to.clone(),
                denom: msg.denom.clone(),
                amount: remote_amount,
                crc_src: msg.crc_src,
                timeout_timestamp,
            },
        )?;

        // build commitment of send_packet
        let mut cell_builder = CellBuilder::new();
        cell_builder.store_bits(32, &SEND_TO_TON_MAGIC_NUMBER.to_be_bytes().to_vec())?; // opcode
        cell_builder.store_bits(32, &msg.crc_src.to_be_bytes().to_vec())?; // crc_src
        cell_builder.store_bits(64, &last_packet_seq.to_be_bytes().to_vec())?; // seq
        cell_builder.store_address(&TonAddress::from_base64_std(&msg.to)?)?; // receiver
        cell_builder.store_address(&TonAddress::from_base64_std(&msg.denom)?)?; // remote denom
        cell_builder.store_bits(128, &remote_amount.to_be_bytes().to_vec())?; // remote amount
        cell_builder.store_bits(64, &timeout_timestamp.to_be_bytes().to_vec())?; // timeout timestamp
        let commitment = cell_builder.build()?.cell_hash()?;
        SEND_PACKET_COMMITMENT.save(
            deps.storage,
            last_packet_seq,
            &to_bytes32(&HexBinary::from(commitment))?,
        )?;

        // this packet is saved just in case we need to refund the sender due to timeout
        TIMEOUT_SEND_PACKET.save(
            deps.storage,
            last_packet_seq,
            &TimeoutSendPacket {
                sender: sender.to_string(),
                local_refund_asset: Asset {
                    info: mapping.asset_info,
                    amount: local_amount,
                },
                timeout_timestamp,
            },
        )?;
        LAST_PACKET_SEQ.save(deps.storage, &last_packet_seq)?;

        Ok(Response::new()
            .add_messages(cosmos_msgs)
            .add_attributes(vec![
                ("action", "bridge_to_ton"),
                ("dest_receiver", &msg.to),
                ("dest_denom", &msg.denom),
                ("local_amount", &local_amount.to_string()),
                ("crc_src", &msg.crc_src.to_string()),
                ("relayer_fee", &fee_data.relayer_fee.amount().to_string()),
                ("token_fee", &fee_data.token_fee.amount().to_string()),
                ("timeout", &timeout_timestamp.to_owned().to_string()),
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
