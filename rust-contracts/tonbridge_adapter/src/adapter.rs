use cosmwasm_std::{Addr, CosmosMsg, Deps, DepsMut, Event, Response, StdResult, Uint128, Uint256};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use tonbridge_parser::{
    bit_reader::{address, read_cell, read_uint256},
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{OPCODE_1, OPCODE_2},
    types::{Address, Bytes32, CellData, Message, TestData},
};

pub trait IBaseAdapter {
    fn execute(
        &self,
        deps: DepsMut,
        boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
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
    token: Cw20Contract,
    transaction_parser: TransactionParser,
}

impl Adapter {
    pub fn new(ton_token: Addr) -> Self {
        Self {
            transaction_parser: Default::default(),
            token: Cw20Contract(ton_token),
        }
    }
}

impl IBaseAdapter for Adapter {
    // FIXME: this function in Solidity is onlyOwner called, not for public!
    fn execute(
        &self,
        deps: DepsMut,
        boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<Vec<CosmosMsg>> {
        self.transaction_parser
            .parse_transaction_header(boc, cells, root_idx)?;
        let cell_idx = read_cell(cells, root_idx);
        let mut messages = self
            .transaction_parser
            .parse_messages_header(boc, cells, cell_idx)?;

        let msg_data = get_data_from_messages(boc, opcode, cells, &mut messages.out_messages)?;

        let receiver = deps.api.addr_humanize(&msg_data.eth_address.into())?;

        let amount = msg_data.amount.try_into()?;
        if opcode == OPCODE_1 {
            self.token.call(Cw20ExecuteMsg::Mint {
                recipient: receiver.to_string(),
                amount: amount * Uint128::from(1000000000u128),
            })?;
            // _token.mint(msg_data.amount * 1000000000, msg_data.eth_address);
        }

        if opcode == OPCODE_2 {
            self.token.call(Cw20ExecuteMsg::Transfer {
                recipient: receiver.to_string(),
                amount,
            })?;
            // receiver.transfer(msg_data.amount);
        }

        // FIXME: return actual cosmos msgs for minting & swapping tokens
        Ok(vec![])
    }

    fn swap_eth(&self, to: Uint256, amount: Uint256) -> Response {
        Response::new()
            .add_event(Event::new("swap_eth"))
            .add_attribute("to", to.to_string())
            .add_attribute("amount", amount.to_string())
    }

    fn swap_token(
        &self,
        deps: Deps,
        from: Address,
        amount: Uint256,
        to: Uint256,
    ) -> StdResult<Response> {
        // _token.burn(from, amount);
        // emit SwapWTONInitialized(to, amount / 1e9);
        let burn_amount = amount / Uint256::from(1000000000u128);

        let owner = deps.api.addr_humanize(&from.into())?.to_string();
        self.token.call(Cw20ExecuteMsg::BurnFrom {
            owner,
            amount: burn_amount.try_into()?,
        })?;

        Ok(Response::new()
            .add_event(Event::new("swap_eth"))
            .add_attribute("to", to.to_string())
            .add_attribute("amount", burn_amount.to_string()))
    }
}

pub fn get_data_from_messages(
    boc_data: &[u8],
    opcode: Bytes32,
    cells: &mut [CellData],
    out_messages: &mut [Message; 5],
) -> StdResult<TestData> {
    let mut data = TestData::default();
    for i in 0..5 {
        if out_messages[i].info.dest.hash == opcode {
            let idx = out_messages[i].body_idx;
            // cells[out_messages[i].body_idx].cursor += 634;
            let hash = read_uint256(boc_data, cells, idx, 256)?.to_be_bytes();
            data.eth_address = address(hash)?;
            data.amount = read_uint256(boc_data, cells, idx, 256)?;
        }
    }

    Ok(data)
}
