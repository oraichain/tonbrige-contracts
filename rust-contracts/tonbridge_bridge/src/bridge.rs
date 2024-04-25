use cosmwasm_std::{Deps, Response, StdResult, Uint256};
use cw_tonbridge_adapter::adapter::{Adapter, IBaseAdapter};
use cw_tonbridge_validator::validator::Validator;
use tonbridge_parser::{
    block_parser::BlockParser,
    transaction_parser::TransactionParser,
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
    types::{Address, Bytes32},
};

pub struct Bridge {
    block_parser: BlockParser,
    transaction_parser: TransactionParser,
    tree_of_cells_parser: TreeOfCellsParser,
    validator: Validator,
}

impl Bridge {
    pub fn read_transaction(
        &self,
        deps: Deps,
        tx_boc: &[u8],
        block_boc: &[u8],
        adapter: &Adapter,
        opcode: Bytes32,
    ) -> StdResult<()> {
        let mut tx_header = self.tree_of_cells_parser.parse_serialized_header(tx_boc)?;
        // BagOfCellsInfo memory blockHeader = self.tree_of_cells_parser
        //     .parseSerializedHeader(block_boc);

        let mut tx_toc = self
            .tree_of_cells_parser
            .get_tree_of_cells(tx_boc, &mut tx_header)?;
        // CellData[100] memory blockToc = self.tree_of_cells_parser.get_tree_of_cells(
        //     block_boc,
        //     blockHeader
        // );

        // require(
        //     self.validator.isVerifiedBlock(blockToc[blockHeader.rootIdx]._hash[0]),
        //     "invalid block"
        // );

        // TransactionHeader memory txInfo = self.transaction_parser
        //     .parseTransactionHeader(tx_boc, tx_toc, tx_header.rootIdx);
        // bool isValid = self.block_parser.parse_block(
        //     block_boc,
        //     blockHeader,
        //     blockToc,
        //     tx_toc[tx_header.rootIdx]._hash[0],
        //     txInfo
        // );

        // require(isValid, "Wrong block for transaction");

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
