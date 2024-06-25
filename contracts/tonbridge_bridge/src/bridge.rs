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
    msg::{BridgeToTonMsg, FeeData, Ics20Packet},
    parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id},
    state::{MappingMetadata, Ratio, SendPacket},
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
    state::{ics20_denoms, CONFIG, LAST_PACKET_SEQ, PROCESSED_TXS, SEND_PACKET, TOKEN_FEE},
};

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
                Bridge::handle_packet_receive(storage, api, &querier, packet_data, mapping)?;
            cosmos_msgs.append(&mut res.0);
            attrs.append(&mut res.1);
        }
        Ok((cosmos_msgs, attrs))
    }

    pub fn handle_packet_receive(
        storage: &mut dyn Storage,
        api: &dyn Api,
        querier: &QuerierWrapper,
        data: BridgePacketData,
        mapping: MappingMetadata,
    ) -> StdResult<(Vec<CosmosMsg>, Vec<Attribute>)> {
        let config = CONFIG.load(storage)?;
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
                    return Err(StdError::generic_err("Cannot mint a native token"))
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

    pub fn validate_basic_ics20_packet(
        packet: &Ics20Packet,
        amount: &Uint128,
        denom: &str,
        sender: &str,
    ) -> StdResult<()> {
        if packet.amount.ne(amount) {
            return Err(StdError::generic_err(format!(
                "Sent amount {:?} is not equal to amount given in boc, which is {:?}",
                amount, packet.amount
            )));
        }
        if packet.denom.ne(denom) {
            return Err(StdError::generic_err(format!(
                "Denom {:?} is not equal to denom given in boc, which is {:?}",
                denom, packet.denom
            )));
        }
        if packet.sender.ne(sender) {
            return Err(StdError::generic_err(format!(
                "Sender {:?} is not equal to sender given in boc, which is {:?}",
                sender, packet.sender
            )));
        }
        Ok(())
    }

    pub fn handle_bridge_to_ton(
        deps: DepsMut,
        env: Env,
        msg: BridgeToTonMsg,
        amount: Amount,
        _sender: Addr,
    ) -> Result<Response, ContractError> {
        if amount.is_empty() {
            return Err(ContractError::NoFunds {});
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

        let token_fee_str = &fee_data.token_fee.amount().to_string();
        let relayer_fee_str = &fee_data.relayer_fee.amount().to_string();
        let denom_str = &msg.denom;
        let local_amount_str = &fee_data.deducted_amount.to_string();
        let crc_str = &msg.crc_src.to_string();
        let attributes = vec![
            ("action", "bridge_to_ton"),
            ("dest_receiver", &msg.to),
            ("dest_denom", denom_str),
            ("local_amount", local_amount_str),
            ("crc_src", crc_str),
            ("relayer_fee", relayer_fee_str),
            ("token_fee", token_fee_str),
        ];

        // if our fees have drained the initial amount entirely, then we just get all the fees and that's it
        //  // if our fees have drained the initial amount entirely, then we just get all the fees and that's it
        if fee_data.deducted_amount.is_zero() {
            return Ok(Response::new()
                .add_messages(cosmos_msgs)
                .add_attributes(attributes)
                .add_attributes(vec![("remote_amount", "0")]));
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

        let last_packet_seq = LAST_PACKET_SEQ.may_load(deps.storage)?.unwrap_or_default();

        SEND_PACKET.save(
            deps.storage,
            last_packet_seq + 1,
            &SendPacket {
                sequence: last_packet_seq + 1,
                to: msg.to.clone(),
                denom: msg.denom.clone(),
                amount: remote_amount,
                crc_src: msg.crc_src,
            },
        )?;
        LAST_PACKET_SEQ.save(deps.storage, &(last_packet_seq + 1))?;

        Ok(Response::new()
            .add_messages(cosmos_msgs)
            .add_attributes(vec![("remote_amount", &remote_amount.to_string())]))
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

#[cfg(test)]
mod tests {

    use cosmwasm_std::{testing::mock_dependencies, to_binary, Addr, Empty, HexBinary, Uint128};
    use cw20::{BalanceResponse, Cw20Coin};
    use oraiswap::asset::AssetInfo;
    use tonbridge_bridge::{msg::UpdatePairMsg, state::SendPacket};

    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    use crate::{contract::execute_submit_bridge_to_ton_info, state::SEND_PACKET};

    fn validator_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            cw_tonbridge_validator::contract::execute,
            cw_tonbridge_validator::contract::instantiate,
            cw_tonbridge_validator::contract::query,
        );
        Box::new(contract)
    }

    fn bridge_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    fn dummy_cw20_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            cw20_base::contract::execute,
            cw20_base::contract::instantiate,
            cw20_base::contract::query,
        );
        Box::new(contract)
    }

    #[test]
    fn test_read_transaction() {
        let mut app = App::default();
        let admin = Addr::unchecked("admin");
        let validator_contract = validator_contract();
        let bridge_contract = bridge_contract();
        let dummy_cw20_contract = dummy_cw20_contract();
        let validator_id = app.store_code(validator_contract);
        let bridge_id = app.store_code(bridge_contract);
        let cw20_id = app.store_code(dummy_cw20_contract);
        let bridge_cw20_balance = Uint128::from(10000000000000001u64);

        let validator_addr = app
            .instantiate_contract(
                validator_id,
                admin.clone(),
                &tonbridge_validator::msg::InstantiateMsg { boc: None },
                &vec![],
                "validator".to_string(),
                None,
            )
            .unwrap();

        let bridge_addr = app
            .instantiate_contract(
                bridge_id,
                admin.clone(),
                &tonbridge_bridge::msg::InstantiateMsg {
                    bridge_adapter: "EQAE8anZidQFTKcsKS_98iDEXFkvuoa1YmVPxQC279zAoV7R".to_string(),
                    relayer_fee_token: AssetInfo::NativeToken {
                        denom: "orai".to_string(),
                    },
                    token_fee_receiver: Addr::unchecked("token_fee"),
                    relayer_fee_receiver: Addr::unchecked("relayer_fee"),
                    relayer_fee: None,
                    swap_router_contract: "router".to_string(),
                },
                &vec![],
                "bridge".to_string(),
                None,
            )
            .unwrap();

        let cw20_addr = app
            .instantiate_contract(
                cw20_id,
                admin.clone(),
                &cw20_base::msg::InstantiateMsg {
                    name: "Dummy".to_string(),
                    symbol: "DUMMY".to_string(),
                    decimals: 6,
                    initial_balances: vec![{
                        Cw20Coin {
                            address: bridge_addr.to_string(),
                            amount: bridge_cw20_balance,
                        }
                    }],
                    mint: None,
                    marketing: None,
                },
                &vec![],
                "dummy".to_string(),
                None,
            )
            .unwrap();

        let tx_boc = HexBinary::from_hex("b5ee9c72010210010002a00003b5704f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1000014c775004781596aa8bae813b9e6a71ade2ba8a393b7b1fff5c20db8414268e761e80f445466000014c774a4ba016675543a00034671e79e80102030201e00405008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d02170447c90ec90dd418656798110e0f01b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700013c6a766275015329cb0a4bff7c883117164beea1ad589953f1402dbbf7302850ec90dd400613faa00000298ee9a50184cceaa864c0060101df080118af35dc850000000000000000070155ffff801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d00010a019fe000278d4ecc4ea02a653961497fef910622e2c97dd435ab132a7e2805b77ee6050b006b6841e5c7db57b8d076dfa4368dea08e132f2917969b5920fbd8229dc6560d7000014c7750047826675543a60090153801397b648216d9f2f44369a4d6a5d42c41146f4cbc66093a35ba780f4e6a405714e071afd498d0000100a04000c0b0c0d00126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e43758c3d090000000000000000008c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc986db784c36dbc000000000000200000000000390f7bed18b3fc226db7ad9ac1961b38a37b80e826f33ccabfa03d8405819e6ca41902b2c").unwrap();

        let tx_proof = HexBinary::from_hex("b5ee9c7201020e010002cd00094603b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80001d01241011ef55aafffffffd0203040502a09bc7a987000000008401014ceab100000000020000000000000000000000006675543a000014c775004780000014c7750047831736f9b3000446e401361bf701361bd7c400000007000000000000002e06072848010169df3a129570f135f49a71d8b483fa4c1c482f3f66ed85120a88d1b12fa9d16500012848010140bc4dd799a511514e2389685f05400ff4552fd0742fa5bcffc54f5628ba2728001c23894a33f6fde40b062e4f9ca75cdd7575e0d2ad61010f65e76ead272c60375bbdf85721963d37da28343e390d3d0fcc100f52754cdd13a8e4b655b0b6d5953c09f2f928d8ce4008090a0098000014c774e1c30401361bf750761c553cb279919d5c01370e223caddc8aed39f253c97e2067fab0d970edb84dfe70fb36e9e9e40e03596ed1ede5e16b95c4ab61817ceac5e86ca43fd7b4480098000014c774f10543014ceab0eadce00e65f2d6771561346ad31884c67e036c6aa63d14ba694d6affdf684810f750e961923988298da0b1dbe93abce9756cc3ef6b72dfd97531c7ce6199cabb28480101a7f5bf430102522e84d0b8b108a45efc71925ce0c6c591ae5ac50e7ead9baa15000828480101db58517b1e79f67b35742f301a407f7edf1b95fae995d949f62cbeb17f10e0e60009210799c79e7a0b22a5a0009e353b313a80a994e58525ffbe44188b8b25f750d6ac4ca9f8a016ddfb98142671e79e504f1a9d989d4054ca72c292ffdf220c45c592fba86b562654fc500b6efdcc0a1a000000a63ba8023c099c79e7a00c0d28480101f12edcfd2cb61fdee42d31cd884d21f92891e1ef9072f3ba4dded90ea5a09f380006008272c22a17f9d66afb94f83e04c02edc5abb7f2a15486ef4beaa703990dbfadb3b4085457ef326f4ecbbe9d81236ead8479f8765194636e87e84ca27eff6a7ec1f1d").unwrap();

        let opcode =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        // shard block with block hash
        let block_hash =
            HexBinary::from_hex("b4107e11da299213c78b889ec423fe1c7de98b508a4fdd113c6990b307235d80")
                .unwrap();

        // set verified for simplicity
        app.execute(
            admin.clone(),
            cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
                contract_addr: validator_addr.to_string(),
                msg: to_binary(&tonbridge_validator::msg::ExecuteMsg::SetVerifiedBlock {
                    root_hash: block_hash,
                    seq_no: 1,
                })
                .unwrap(),
                funds: vec![],
            }),
        )
        .unwrap();

        app.execute(
            admin.clone(),
            cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
                contract_addr: bridge_addr.to_string(),
                msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::UpdateMappingPair(
                    UpdatePairMsg {
                        local_channel_id: "channel-0".to_string(),
                        denom: "EQCcvbJBC2z5eiG00mtS6hYgijemXjMEnRrdPAenNSAringl".to_string(),
                        local_asset_info: AssetInfo::Token {
                            contract_addr: Addr::unchecked(cw20_addr.clone()),
                        },
                        remote_decimals: 6,
                        local_asset_info_decimals: 6,
                        opcode,
                    },
                ))
                .unwrap(),
                funds: vec![],
            }),
        )
        .unwrap();

        app.execute(
            admin.clone(),
            cosmwasm_std::CosmosMsg::Wasm(cosmwasm_std::WasmMsg::Execute {
                contract_addr: bridge_addr.to_string(),
                msg: to_binary(&tonbridge_bridge::msg::ExecuteMsg::ReadTransaction {
                    tx_proof,
                    tx_boc,
                    validator_contract_addr: validator_addr.to_string(),
                })
                .unwrap(),
                funds: vec![],
            }),
        )
        .unwrap();

        let bridge_balance: BalanceResponse = app
            .wrap()
            .query_wasm_smart(
                cw20_addr.clone(),
                &cw20_base::msg::QueryMsg::Balance {
                    address: bridge_addr.to_string(),
                },
            )
            .unwrap();

        println!("bridge balance: {:?}", bridge_balance);
    }

    #[test]
    fn test_submit_bridge_to_ton_info() {
        let mut deps = mock_dependencies();
        SEND_PACKET
            .save(
                deps.as_mut().storage,
                1,
                &SendPacket {
                    sequence: 1,
                    to: "EQABEq658dLg1KxPhXZxj0vapZMNYevotqeINH786lpwwSnT".to_string(),
                    denom: "EQAcXN7ZRk927VwlwN66AHubcd-6X3VhiESEWsE2k63AICIN".to_string(),
                    amount: Uint128::from(10000000000u128),
                    crc_src: 82134516,
                },
            )
            .unwrap();

        let data = "000000000000000180002255D73E3A5C1A9589F0AECE31E97B54B261AC3D7D16D4F1068FDF9D4B4E18300071737B65193DDBB57097037AE801EE6DC77EE97DD5862112116B04DA4EB70080000000000000000000000009502F9000139517D2";
        execute_submit_bridge_to_ton_info(deps.as_mut(), HexBinary::from_hex(data).unwrap())
            .unwrap();
    }
}
