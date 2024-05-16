use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    Addr, Binary, CosmosMsg, Deps, DepsMut, Response, StdError, StdResult, Uint256,
};
use tonbridge_adapter::adapter::{Adapter, IBaseAdapter};
use tonbridge_parser::{
    block_parser::{BlockParser, IBlockParser},
    transaction_parser::{ITransactionParser, TransactionParser},
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
    types::{Address, Bytes32},
};
use tonbridge_validator::wrapper::ValidatorWrapper;

use crate::state::PROCESSED_TXS;

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
        tx_boc: &[u8],
        block_boc: &[u8],
        adapter: &Adapter,
        opcode: Bytes32,
    ) -> StdResult<Vec<CosmosMsg>> {
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

        let root_hash = block_toc[block_header.root_idx].hashes[0];

        let is_block_verified = self
            .validator
            .is_verified_block(&deps.querier, Binary::from(&root_hash))?;
        if !is_block_verified {
            return Err(StdError::generic_err(
                "The block is not verified or invalid. Cannot bridge!",
            ));
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
            root_hash,
            &mut tx_info,
        )?;
        if !is_tx_in_correct_block {
            return Err(StdError::generic_err("Wrong block for transaction"));
        }

        let is_tx_processed = PROCESSED_TXS
            .may_load(deps.storage, &tx_info.address_hash)?
            .unwrap_or(false);

        if is_tx_processed {
            return Err(StdError::generic_err("This tx has already been processed"));
        }

        PROCESSED_TXS.save(deps.storage, &tx_info.address_hash, &true)?;
        adapter.execute(deps, tx_boc, opcode, &mut tx_toc, tx_header.root_idx)
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
}
