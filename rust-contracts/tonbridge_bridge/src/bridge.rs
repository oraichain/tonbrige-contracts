use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, CosmosMsg, Deps, DepsMut, HexBinary, Response, StdError, StdResult, Uint128, Uint256,
};
use tonbridge_adapter::adapter::{Adapter, IBaseAdapter};
use tonbridge_bridge::{
    msg::Ics20Packet,
    parser::{get_key_ics20_ibc_denom, parse_ibc_wasm_port_id},
};
use tonbridge_parser::{
    block_parser::{BlockParser, IBlockParser},
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
    types::{Address, Bytes32},
};
use tonbridge_validator::wrapper::ValidatorWrapper;
use tonlib::cell::BagOfCells;

use crate::{
    channel::increase_channel_balance,
    error::ContractError,
    state::{ics20_denoms, PROCESSED_TXS},
};

#[cw_serde]
pub struct Bridge {
    pub block_parser: BlockParser,
    pub transaction_parser: TransactionParser,
    pub tree_of_cells_parser: TreeOfCellsParser,
    pub validator: ValidatorWrapper,
}

impl Bridge {
    pub fn new(validator_contract_addr: Addr) -> Self {
        Self {
            block_parser: BlockParser::default(),
            transaction_parser: TransactionParser::default(),
            tree_of_cells_parser: TreeOfCellsParser::default(),
            validator: ValidatorWrapper(validator_contract_addr),
        }
    }
}

impl Bridge {
    pub fn read_transaction(
        &self,
        deps: DepsMut,
        contract_address: &str,
        tx_boc: &[u8],
        block_boc: &[u8],
        opcode: Bytes32,
    ) -> Result<Vec<CosmosMsg>, ContractError> {
        let mut tx_header = self.tree_of_cells_parser.parse_serialized_header(tx_boc)?;
        let mut block_header = self
            .tree_of_cells_parser
            .parse_serialized_header(block_boc)?;

        let mut tx_toc = self
            .tree_of_cells_parser
            .get_tree_of_cells(tx_boc, &mut tx_header)?;

        let mut block_toc = self
            .tree_of_cells_parser
            .get_tree_of_cells(block_boc, &mut block_header)?;

        let cells = BagOfCells::parse(block_boc)?;
        let first_root = cells.single_root()?;

        let root_hash = first_root.hashes[0].clone();
        let is_block_verified = self
            .validator
            .is_verified_block(&deps.querier, HexBinary::from(root_hash))?;

        if !is_block_verified {
            return Err(ContractError::Std(StdError::generic_err(
                "The block is not verified or invalid. Cannot bridge!",
            )));
        }

        let mut tx_info = self.transaction_parser.parse_transaction_header(
            tx_boc,
            &mut tx_toc,
            tx_header.root_idx,
        )?;

        let is_tx_in_correct_block = self.block_parser.parse_block(
            block_boc,
            &mut block_header,
            &mut block_toc,
            tx_toc[tx_header.root_idx].hashes[0],
            &mut tx_info,
        )?;
        if !is_tx_in_correct_block {
            return Err(ContractError::Std(StdError::generic_err(
                "Wrong block for transaction",
            )));
        }

        let is_tx_processed = PROCESSED_TXS
            .may_load(deps.storage, &tx_info.address_hash)?
            .unwrap_or(false);

        if is_tx_processed {
            return Err(ContractError::Std(StdError::generic_err(
                "This tx has already been processed",
            )));
        }

        PROCESSED_TXS.save(deps.storage, &tx_info.address_hash, &true)?;
        let adapter = Adapter::new();
        // FIXME: packet data should have something for the bridge contract to query mapping pair
        let mut packet_data =
            adapter.parse_packet_data(tx_boc, opcode, &mut tx_toc, tx_header.root_idx)?;
        // FIXME: remove hardcode amount + 1 to amount. +1 here for test cases
        packet_data.amount = packet_data.amount.checked_add(Uint256::one())?;

        // FIXME: remove hardcode ics denom key
        let channel_id = "";
        let denom = "";

        let mapping = ics20_denoms().load(
            deps.storage,
            &get_key_ics20_ibc_denom(&parse_ibc_wasm_port_id(contract_address), channel_id, denom),
        )?;
        increase_channel_balance(
            deps.storage,
            channel_id,
            denom,
            packet_data.amount.try_into()?,
        )?;
        let msgs = adapter.execute(deps, packet_data, opcode, mapping)?;
        Ok(msgs)
    }

    pub fn swap_eth(to: Uint256, amount: Uint256, adapter: &Adapter) -> Response {
        adapter.swap_eth(to, amount)
    }

    pub fn swap_token(
        &self,
        deps: Deps,
        from: Address,
        amount: Uint256,
        to: Uint256,
        adapter: &Adapter,
    ) -> StdResult<Response> {
        adapter.swap_token(deps, from, amount, to)
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
}
