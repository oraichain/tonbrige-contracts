use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult};
use tonbridge_parser::{
    bit_reader::{
        parse_dict, read_bit, read_bool, read_bytes32_bit_size, read_u16, read_u32, read_u64,
        read_u8,
    },
    block_parser::BLOCK_INFO_CELL,
    types::{Bytes32, CellData, VerifiedBlockInfo},
};

pub const SHARD_STATE_CELL: u32 = 0x9023afe2;
pub const MC_EXTRA_STATE_CELL: u16 = 0xcc26;
pub const MESSAGE_PREFIX: [u8; 4] = [0x70, 0x6e, 0x0b, 0xc5];

pub trait IShardValidator {
    fn parse_shard_proof_path(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])>;

    fn add_prev_block(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])>;

    fn read_master_proof(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<Bytes32>;

    fn read_state_proof(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
        // bytes32 root_hash
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])>;
}

#[cw_serde]
#[derive(Default)]
pub struct ShardValidator {}

impl IShardValidator for ShardValidator {
    fn parse_shard_proof_path(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])> {
        // check root cell is special
        if !toc[root_idx].special {
            return Err(StdError::generic_err("root is not exotic"));
        }

        let mut root_hashes = [Bytes32::default(); 10];
        let mut blocks = [VerifiedBlockInfo::default(); 10];
        let mut cell_idx = toc[root_idx].refs[0];
        // require(isVerifiedBlock(toc[cell_idx]._hash[0]), "Not verified");
        // block skip cells
        cell_idx = toc[cell_idx].refs[3];
        cell_idx = toc[cell_idx].refs[3];
        cell_idx = toc[cell_idx].refs[0];

        // require(0xcc26 == read_u16(boc, toc, cell_idx, 16), "not a McStateExtra");

        let tx_idxs = parse_dict(boc, toc, cell_idx, 32)?;

        let mut free_i = 0;
        for i in 0..32 {
            if tx_idxs[i] == 255 {
                break;
            }
            // todo: loop for loadBinTree
            let mut bin_tree_cells = [0usize; 32];
            bin_tree_cells[0] = tx_idxs[i];
            let mut j = 0;
            while bin_tree_cells[0] != 0 {
                let leaf_idx = bin_tree_cells[j]; // toc[tx_idxs[i]].refs[0];
                bin_tree_cells[j] = 0;

                if read_bit(boc, toc, leaf_idx) == 0 {
                    let d_type = read_u8(boc, toc, leaf_idx, 4)?;

                    if !(d_type == 0xa || d_type == 0xb) {
                        return Err(StdError::generic_err("not a ShardDescr"));
                    }

                    if free_i < 10 {
                        blocks[free_i].verified = true;
                        blocks[free_i].seq_no = read_u32(boc, toc, leaf_idx, 32)?;

                        // uint32 seq_no = read_u32(boc, toc, leaf_idx, 32);
                        // uint32 req_mc_seqno =
                        read_u32(boc, toc, leaf_idx, 32)?;
                        blocks[free_i].start_lt = read_u64(boc, toc, leaf_idx, 64)?;
                        blocks[free_i].end_lt = read_u64(boc, toc, leaf_idx, 64)?;
                        root_hashes[free_i] = read_bytes32_bit_size(boc, toc, leaf_idx, 256);
                        // bytes32 file_hash = read_bytes32_bit_size(
                        //     boc,
                        //     toc,
                        //     leaf_idx,
                        //     256
                        // );

                        free_i += 1;
                    }
                    // verifiedBlocks[root_hash] = new_block_info;
                } else {
                    if toc[leaf_idx].refs[0] != 255 {
                        // j += 1;
                        bin_tree_cells[j] = toc[leaf_idx].refs[0];
                    }
                    if toc[leaf_idx].refs[1] != 255 {
                        j += 1;
                        bin_tree_cells[j] = toc[leaf_idx].refs[1];
                    }
                }
                if j > 0 && bin_tree_cells[j] == 0 {
                    j -= 1;
                }
            }
        }
        Ok((root_hashes, blocks))
    }

    fn add_prev_block(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])> {
        // check root cell is special
        if !toc[root_idx].special {
            return Err(StdError::generic_err("root is not exotic"));
        }

        let mut root_hashes = [Bytes32::default(); 10];
        let mut blocks = [VerifiedBlockInfo::default(); 10];
        let mut cell_idx = toc[root_idx].refs[0];
        // require(isVerifiedBlock(toc[cell_idx]._hash[0]), "Not verified");
        cell_idx = toc[cell_idx].refs[0];

        if read_u32(boc, toc, cell_idx, 32)? != BLOCK_INFO_CELL {
            return Err(StdError::generic_err("not a BlockInfo"));
        }

        read_u32(boc, toc, cell_idx, 32)?;
        let not_master = read_bool(boc, toc, cell_idx);
        let after_merge = read_bool(boc, toc, cell_idx);

        cell_idx = if not_master {
            toc[cell_idx].refs[1]
        } else {
            toc[cell_idx].refs[0]
        };

        let mut free_i = 0;
        if !after_merge {
            update_block(
                boc,
                toc,
                cell_idx,
                &mut root_hashes,
                &mut blocks,
                &mut free_i,
                false,
            )?;

            // data.prev = loadExtBlkRef(cell, t);
        } else {
            if toc[cell_idx].refs[0] != 255 {
                update_block(
                    boc,
                    toc,
                    toc[cell_idx].refs[0],
                    &mut root_hashes,
                    &mut blocks,
                    &mut free_i,
                    false,
                )?;
            }

            if toc[cell_idx].refs[1] != 255 {
                update_block(
                    boc,
                    toc,
                    toc[cell_idx].refs[1],
                    &mut root_hashes,
                    &mut blocks,
                    &mut free_i,
                    false,
                )?;
            }

            // data.prev1 = loadRefIfExist(cell, t, loadExtBlkRef);
            // data.prev2 = loadRefIfExist(cell, t, loadExtBlkRef);
        }

        Ok((root_hashes, blocks))
    }

    fn read_master_proof(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
    ) -> StdResult<Bytes32> {
        // extra
        let cell_idx = toc[root_idx].refs[2];
        read_u8(boc, toc, cell_idx, 8)?;
        // bytes32 old_hash =
        read_bytes32_bit_size(boc, toc, cell_idx, 256);
        let new_hash = read_bytes32_bit_size(boc, toc, cell_idx, 256);

        // verifiedBlocks[toc[root_idx]._hash[0]].new_hash = new_hash;

        Ok(new_hash)
    }

    fn read_state_proof(
        &self,
        boc: &[u8],
        root_idx: usize,
        toc: &mut [CellData],
        // bytes32 root_hash
    ) -> StdResult<([Bytes32; 10], [VerifiedBlockInfo; 10])> {
        let mut free_i = 0;

        if read_u32(boc, toc, root_idx, 32)? != SHARD_STATE_CELL {
            return Err(StdError::generic_err("not a ShardStateUnsplit"));
        };

        // custom
        let mut cell_idx = toc[root_idx].refs[3];
        let mut root_hashes = [Bytes32::default(); 10];
        let mut blocks = [VerifiedBlockInfo::default(); 10];

        if read_u16(boc, toc, cell_idx, 16)? != MC_EXTRA_STATE_CELL {
            return Err(StdError::generic_err("not a McStateExtra"));
        }

        // prev_blocks
        cell_idx = toc[cell_idx].refs[2];

        let tx_idxs = parse_dict(boc, toc, cell_idx, 30)?;

        for i in 0..32 {
            if tx_idxs[i] == 255 {
                break;
            }

            toc[tx_idxs[i]].cursor += 66;

            update_block(
                boc,
                toc,
                tx_idxs[i],
                &mut root_hashes,
                &mut blocks,
                &mut free_i,
                true,
            )?;
        }

        // require(state_hash == verifiedBlocks[toc[root_idx]._hash[0]].new_hash);

        // state_hash -> -> addToVerifiedBlocks[cell (list) .blk_ref]

        Ok((root_hashes, blocks))
    }
}

fn update_block(
    boc: &[u8],
    toc: &mut [CellData],
    cell_idx: usize,
    root_hashes: &mut [Bytes32; 10],
    blocks: &mut [VerifiedBlockInfo; 10],
    free_i: &mut usize,
    update_new_hash: bool,
) -> StdResult<()> {
    let end_lt = read_u64(boc, toc, cell_idx, 64)?;
    let seq_no = read_u32(boc, toc, cell_idx, 32)?;
    let root_hash = read_bytes32_bit_size(boc, toc, cell_idx, 256);

    let new_hash = update_new_hash.then(|| read_bytes32_bit_size(boc, toc, cell_idx, 256));

    // verifiedBlocks[root_hash] = VerifiedBlockInfo(
    //     true,
    //     seq_no,
    //     0,
    //     end_lt,
    //     0
    // );
    if *free_i < 10 {
        root_hashes[*free_i] = root_hash;
        blocks[*free_i].verified = true;
        blocks[*free_i].seq_no = seq_no;
        blocks[*free_i].end_lt = end_lt;

        if let Some(new_hash) = new_hash {
            blocks[*free_i].new_hash = new_hash
        }

        *free_i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    fn increase(i: &mut u8) {
        *i += 1;
    }

    #[test]
    fn test_mut() {
        let mut i = 10;
        increase(&mut i);
        println!("{}", i);
    }
}
