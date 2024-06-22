use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Api, CosmosMsg, DepsMut, Env, HexBinary, QuerierWrapper, Response, StdError, StdResult,
    Uint128,
};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw20_ics20_msg::amount::{convert_local_to_remote, convert_remote_to_local, Amount};
use oraiswap::asset::{Asset, AssetInfo};
use tonbridge_bridge::{
    msg::{BridgeToTonMsg, Ics20Packet},
    parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id},
    state::MappingMetadata,
};
use tonbridge_parser::{
    bit_reader::to_bytes32,
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{OPCODE_1, OPCODE_2},
    types::{BridgePacketData, Bytes32},
};
use tonbridge_validator::wrapper::ValidatorWrapper;
use tonlib::{
    cell::{BagOfCells, Cell},
    responses::MessageType,
};

use crate::{
    channel::{decrease_channel_balance, increase_channel_balance},
    error::ContractError,
    state::{ics20_denoms, SendPacket, LAST_PACKET_SEQ, PROCESSED_TXS, SEND_PACKET},
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
        opcode: Bytes32,
    ) -> Result<Vec<CosmosMsg>, ContractError> {
        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];

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
        for (_, out_msg) in transaction.out_msgs.into_values().enumerate() {
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
            let cell = cell.unwrap().cell;

            let packet_data = tx_parser.parse_packet_data(&cell)?.to_pretty()?;

            let mapping = ics20_denoms().load(
                storage,
                &get_key_ics20_ibc_denom(
                    &parse_ibc_wasm_port_id(contract_address),
                    &packet_data.dest_channel,
                    &packet_data.denom,
                ),
            )?;
            increase_channel_balance(
                storage,
                &packet_data.dest_channel,
                &packet_data.denom,
                packet_data.amount,
            )?;
            // let channel_id = "";
            // let denom = "";

            // let mapping = ics20_denoms().load(
            //     storage,
            //     &get_key_ics20_ibc_denom(
            //         &parse_ibc_wasm_port_id(contract_address),
            //         channel_id,
            //         denom,
            //     ),
            // )?;
            // increase_channel_balance(storage, channel_id, denom, packet_data.amount)?;
            let mut msgs =
                Bridge::handle_packet_receive(api, &querier, packet_data, opcode, mapping)?;
            cosmos_msgs.append(&mut msgs);
        }
        Ok(cosmos_msgs)
    }

    pub fn handle_packet_receive(
        api: &dyn Api,
        querier: &QuerierWrapper,
        data: BridgePacketData,
        opcode: Bytes32,
        mapping: MappingMetadata,
    ) -> StdResult<Vec<CosmosMsg>> {
        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
        let recipient = api.addr_validate(&data.orai_address)?;

        let remote_amount: Uint128 = data.amount;
        let local_amount = convert_remote_to_local(
            remote_amount,
            mapping.remote_decimals,
            mapping.asset_info_decimals,
        )?;
        let msg = Asset {
            info: mapping.asset_info.clone(),
            amount: local_amount,
        };
        if opcode == OPCODE_1 {
            let msg = match msg.info {
                AssetInfo::NativeToken { denom: _ } => {
                    return Err(StdError::generic_err("Cannot mint a native token"))
                }
                AssetInfo::Token { contract_addr } => {
                    Cw20Contract(contract_addr).call(Cw20ExecuteMsg::Mint {
                        recipient: recipient.to_string(),
                        amount: local_amount,
                    })
                }
            }?;
            cosmos_msgs.push(msg);
        } else if opcode == OPCODE_2 {
            cosmos_msgs.push(msg.into_msg(None, querier, recipient)?);
        }

        Ok(cosmos_msgs)
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

        // TODO: Process deduct fee

        let local_amount: Uint128 = amount.amount();
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

        let last_packet_seq = LAST_PACKET_SEQ.may_load(deps.storage)?.unwrap_or_default();

        SEND_PACKET.save(
            deps.storage,
            last_packet_seq + 1,
            &SendPacket {
                sequence: last_packet_seq,
                to: msg.to.clone(),
                denom: msg.denom.clone(),
                amount: remote_amount,
                crc_src: msg.crc_src,
            },
        )?;
        LAST_PACKET_SEQ.save(deps.storage, &(last_packet_seq + 1))?;

        Ok(Response::new().add_attributes(vec![
            ("action", "bridge_to_ton"),
            ("dest_receiver", &msg.to),
            ("dest_denom", &msg.denom),
            ("local_amount", &local_amount.to_string()),
            ("remote_amount", &remote_amount.to_string()),
            ("crc_src", &msg.crc_src.to_string()),
        ]))
    }
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::{testing::mock_dependencies, to_binary, Addr, Empty, HexBinary, Uint128};
    use cw20::{BalanceResponse, Cw20Coin};
    use oraiswap::asset::AssetInfo;
    use tonbridge_bridge::msg::UpdatePairMsg;

    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    use crate::{
        contract::execute_submit_bridge_to_ton_info,
        state::{SendPacket, SEND_PACKET},
    };

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
        let bridge_cw20_balance = Uint128::from(1000000001u64);

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
                    fee_denom: "orai".to_string(),
                    token_fee_receiver: Addr::unchecked("token_fee"),
                    relayer_fee_receiver: Addr::unchecked("relayer_fee"),
                    relayer_fee: None,
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

        let tx_boc = HexBinary::from_hex("b5ee9c7201020a010002800003b5710c3760b686d87bef1f5c5a25e87201a27ef8f5f8805c62ef43700b5a7f6f89c00002aabe17f71c1261bcd503ea556b967295eeaa3d2935ddf3a8e268b87b0349f701490a360c9db00002aabe0113bc16660c34000034641b0de80102030201e004050082726303c5d7b1bc0da5acf09ab3b9cfdffb55ea0ec7f6929c09a76a49932263d1b92e977b92eb9d78b2494efa376962706b566f3b92ab7eea53e12ebdaf034cc0c3020f0c470618a1860440080901e188002186ec16d0db0f7de3eb8b44bd0e40344fdf1ebf100b8c5de86e016b4fedf138034329ed2412425c96cbcb1d44b4bfcb96b693ecf9fa4fac12b64fc913ebae528091837d8e3fd367b28676505f89fbb2bc58f8c32130d9fcba920680a7a24798514d4d18bb33061b6800000018001c060101df0700a062002d40675afa88251845b411ed5e2910e0e15892dea75b0ff286dbcba225cece54a1dcd65000000000000000000000000000000000000036363565623039393662393265643564633736303731353600e968002186ec16d0db0f7de3eb8b44bd0e40344fdf1ebf100b8c5de86e016b4fedf1390016a033ad7d44128c22da08f6af14887070ac496f53ad87f9436de5d112e7672a50ee6b28000608235a00005557c2fee384ccc18680000000001b1b1ab2b1181c9c9b311c9932b21ab2319b9b181b989a9b40009d419d8313880000000000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006fc9830d404c08234c0000000000020000000000028e07461aec104405e30a0eb4866ac725676188a0dfe539c310058492e5ece42040501d0c").unwrap();

        let tx_proof = HexBinary::from_hex("b5ee9c7201021e01000444000946030299328dbd84b0ece362aec8cb04f89f7f21b1908dd55542ae9983914d81b7d1002801241011ef55aaffffff110203040502a09bc7a987000000008001029d9e8900000001020000000000000000000000006660c34000002aabe17f71c000002aabe17f71fa6f2862d90008bf1b024720d0024711a2c400000007000000000000002e0607284801015643265b6cffa70dc9e813a64a3f6e6b6cb2d9eecdd4c0132d7cc8b6f6980234000228480101f1ef4849255d409ea4809cc7af48726e7cba7e8e6a0551120a2191684b576d7b002723894a33f6fdbfde8507db6befffe5a57ad26aadb2f90b7d5beab6b118f0ddad8153bb784b1ac28cac5958bde45d7b4839cd371f8b6d2dbbc6f1626ebb185dd5b03bcce7bbb54008090a009800002aabe1702f84024720d0fe987ca6d7a6c373433d0501a25685d620df208aafe798cbfd3af74103fe9d9310b099470cd8b563a069a8d742321b3f1dfa3c84cc8283b8d90f66cf6f3b4bd0009800002aabe160ed5f029d9e88cbb5b00727d017d06a3e812942605fbbed8510a823bba5be5af7e24649c971ece4a7cf33e0bdb68bd5c222c9b92253dbea5b8ac31fb0122b5e374506e90768a328480101004ff947a10e7a705c6c825569cac87098eb2c125b5fe9f8e95bb91d2b4b8940001828480101aa145fdfa31eb650bd814230f6a9a5b339d9feade846a837416ea3dfed1e5f51001a2109a132c44cb20b220b6109962265900c0d2209106689fbe10e0f2848010185f95f36a058aa0dfedf0274cbf62bc61a5dc4fc3f747771a0b5a4ff2bccd06000142848010143509a6ced216b57d9489df9a7634b3b0606d8c12918dd4defb551cb8fe34fd500142209104c87b6e9101122091032c1051d121328480101a86e1f1f96d15eadcf76cda1d7d7a608e86aa93cdbaad190b83d3748bab2d72800102209101789f79114152848010188cef0c4bf6b35316a6dd1749c7708a562889991a40dbff5652c1f4a7da9251f001222091014fe07211617284801018a3019f94446ea33abccf41a779e4c7c448ea69cb61727b22fb558b7c2208181000922070e170aed181928480101c6f5b7be07850ac1d3638e6bd89328c8fa3cb4caa43a7ee58ba48e43a6336dd0000e28480101e1414eaea227f221b8cdef63756d370621464cdc96e172a3b9b4931061d17a990010220968d3f137901a1b22a1bd0dd82da1b61efbc7d716897a1c80689fbe3d7e201718bbd0dc02d69fdbe270c8361bca2186ec16d0db0f7de3eb8b44bd0e40344fdf1ebf100b8c5de86e016b4fedf1394000002aabe17f71c1320d86f41c1d284801013064f2f17d28bcf9b6dc4fa1a9ab257b0ef5f696c9c609b7304dc7b41215f3bf00062848010125d1ed22d37fa5ec44b4426f00f33ee3f59e527e8252b9da266172d342c0f5fd00030082726303c5d7b1bc0da5acf09ab3b9cfdffb55ea0ec7f6929c09a76a49932263d1b92e977b92eb9d78b2494efa376962706b566f3b92ab7eea53e12ebdaf034cc0c3").unwrap();

        let opcode =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        // shard block with block hash
        let block_hash =
            HexBinary::from_hex("0299328dbd84b0ece362aec8cb04f89f7f21b1908dd55542ae9983914d81b7d1")
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
                        local_channel_id: "".to_string(),
                        denom: "".to_string(),
                        local_asset_info: AssetInfo::Token {
                            contract_addr: Addr::unchecked(cw20_addr.clone()),
                        },
                        remote_decimals: 6,
                        local_asset_info_decimals: 6,
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
                    opcode,
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
