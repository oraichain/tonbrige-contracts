use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, CosmosMsg, Deps, DepsMut, Response, StdResult, Uint256};
use cw_tonbridge_adapter::adapter::{Adapter, IBaseAdapter};
use cw_tonbridge_validator::wrapper::ValidatorWrapper;
use tonbridge_parser::{
    block_parser::BlockParser,
    transaction_parser::TransactionParser,
    tree_of_cells_parser::{ITreeOfCellsParser, TreeOfCellsParser},
    types::{Address, Bytes32},
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
        tx_boc: &[u8],
        block_boc: &[u8],
        adapter: &Adapter,
        opcode: Bytes32,
    ) -> StdResult<Vec<CosmosMsg>> {
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
