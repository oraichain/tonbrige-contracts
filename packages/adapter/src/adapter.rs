use cosmwasm_std::{
    CosmosMsg, Deps, DepsMut, Event, Response, StdError, StdResult, Uint128, Uint256,
};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw20_ics20_msg::amount::convert_remote_to_local;
use oraiswap::asset::{Asset, AssetInfo};
use tonbridge_bridge::state::MappingMetadata;
use tonbridge_parser::{
    bit_reader::read_cell,
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{OPCODE_1, OPCODE_2},
    types::{Address, Bytes32, CellData, PacketData},
};

pub trait IBaseAdapter {
    fn parse_packet_data(
        &self,
        tx_boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<PacketData>;
    fn execute(
        &self,
        deps: DepsMut,
        data: PacketData,
        opcode: Bytes32,
        bridge_token_mapping: MappingMetadata,
    ) -> StdResult<Vec<CosmosMsg>>;
    fn swap_eth(&self, to: Uint256, amount: Uint256) -> Response; // payable => hook
    fn swap_token(
        &self,
        deps: Deps,
        from: Address,
        amount: Uint256,
        to: Uint256,
    ) -> StdResult<Response>;
}

pub struct Adapter {
    transaction_parser: TransactionParser,
}

impl Adapter {
    pub fn new() -> Self {
        Self {
            transaction_parser: Default::default(),
        }
    }
}

impl IBaseAdapter for Adapter {
    fn parse_packet_data(
        &self,
        tx_boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<PacketData> {
        self.transaction_parser
            .parse_transaction_header(tx_boc, cells, root_idx)?;
        let cell_idx = read_cell(cells, root_idx);
        let mut messages = self
            .transaction_parser
            .parse_messages_header(tx_boc, cells, cell_idx)?;

        let msg_data = self.transaction_parser.get_data_from_messages(
            tx_boc,
            opcode,
            cells,
            &mut messages.out_messages,
        )?;
        Ok(msg_data)
    }

    fn execute(
        &self,
        deps: DepsMut,
        data: PacketData,
        opcode: Bytes32,
        mapping: MappingMetadata,
    ) -> StdResult<Vec<CosmosMsg>> {
        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
        let recipient = deps.api.addr_humanize(&data.receiving_address.into())?;

        let remote_amount: Uint128 = data.amount.try_into()?;
        let local_amount = convert_remote_to_local(
            remote_amount,
            mapping.remote_decimals,
            mapping.asset_info_decimals,
        )?;
        let msg = Asset {
            info: mapping.asset_info.clone(),
            amount: local_amount.clone(),
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
            cosmos_msgs.push(msg.into_msg(None, &deps.querier, recipient)?);
        }

        Ok(cosmos_msgs)
    }

    fn swap_eth(&self, to: Uint256, amount: Uint256) -> Response {
        Response::new()
            .add_event(Event::new("swap_eth"))
            .add_attribute("to", to.to_string())
            .add_attribute("amount", amount.to_string())
    }

    fn swap_token(
        &self,
        _deps: Deps,
        _from: Address,
        amount: Uint256,
        to: Uint256,
    ) -> StdResult<Response> {
        // _token.burn(from, amount);
        // emit SwapWTONInitialized(to, amount / 1e9);
        let burn_amount = amount / Uint256::from(1000000000u128);

        // let owner = deps.api.addr_humanize(&from.into())?.to_string();
        // self.token.call(Cw20ExecuteMsg::BurnFrom {
        //     owner,
        //     amount: burn_amount.try_into()?,
        // })?;

        Ok(Response::new()
            .add_event(Event::new("swap_eth"))
            .add_attribute("to", to.to_string())
            .add_attribute("amount", burn_amount.to_string()))
    }
}
