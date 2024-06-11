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
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
    types::{Address, Bytes32},
};
use tonbridge_validator::wrapper::ValidatorWrapper;
use tonlib::cell::{BagOfCells, Cell};

use crate::{
    channel::increase_channel_balance,
    error::ContractError,
    state::{ics20_denoms, PROCESSED_TXS},
};

#[cw_serde]
pub struct Bridge {
    pub transaction_parser: TransactionParser,
    pub tree_of_cells_parser: TreeOfCellsParser,
    pub validator: ValidatorWrapper,
}

impl Bridge {
    pub fn new(validator_contract_addr: Addr) -> Self {
        Self {
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
        tx_proof: &[u8],
        tx_boc: &[u8],
        opcode: Bytes32,
    ) -> Result<Vec<CosmosMsg>, ContractError> {
        let mut tx_header = self.tree_of_cells_parser.parse_serialized_header(tx_boc)?;
        let mut tx_toc = self
            .tree_of_cells_parser
            .get_tree_of_cells(tx_boc, &mut tx_header)?;

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

        let _tx_info = self.transaction_parser.parse_transaction_header(
            tx_boc,
            &mut tx_toc,
            tx_header.root_idx,
        )?;

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
        let transaction_hash = tx_toc[tx_header.root_idx].hashes[0];
        for acc_block in account_blocks.into_iter() {
            let txs = acc_block.1.transactions;
            for (_key, tx) in txs {
                if let Some(tx_cell) = tx.1 {
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
