use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult, Uint256};

use crate::bit_reader::sha256;

use super::{
    bit_reader::{
        log2ceil, parse_dict, read_bit, read_bool, read_bytes32_bit_size, read_bytes32_byte_size,
        read_cell, read_u16, read_u32, read_u64, read_u8, read_uint256, read_unary_length,
    },
    types::{
        BagOfCellsInfo, Bytes32, CachedCell, CellData, TransactionHeader, ValidatorDescription,
    },
};

pub const BLOCK_INFO_CELL: u32 = 0x9bc7a987;
pub const BLOCK_EXTRA_CELL: u16 = 0xcca5;
pub type ValidatorSet20 = [ValidatorDescription; 20];
pub type ValidatorSet32 = [ValidatorDescription; 32];

pub trait IBlockParser {
    fn parse_candidates_root_block(
        &self,
        boc: &[u8],
        root_idx: usize,
        tree_of_cells: &mut [CellData],
    ) -> StdResult<ValidatorSet32>;

    fn parse_part_validators(
        &self,
        data: &[u8],
        cell_idx: usize,
        cells: &mut [CellData],
        prefix_length: u128,
    ) -> StdResult<ValidatorSet32>;

    fn parse_block(
        &self,
        proof_boc: &[u8],
        proof_boc_info: &mut BagOfCellsInfo,
        proof_tree_of_cells: &mut [CellData],
        tx_root_hash: Bytes32,
        transaction: &mut TransactionHeader,
    ) -> StdResult<bool>;
}

#[cw_serde]
#[derive(Default)]
pub struct BlockParser {}

impl IBlockParser for BlockParser {
    fn parse_candidates_root_block(
        &self,
        boc: &[u8],
        root_idx: usize,
        tree_of_cells: &mut [CellData],
    ) -> StdResult<ValidatorSet32> {
        // uint32 tag =
        read_u32(boc, tree_of_cells, root_idx, 32)?;

        // extra
        let mut cell_idx = tree_of_cells[root_idx].refs[3];
        let test = read_u32(boc, tree_of_cells, cell_idx, 32)?;
        if test != 0x4a33f6fd {
            return Err(StdError::generic_err("not a BlockExtra"));
        }

        // McBlockExtra
        cell_idx = tree_of_cells[cell_idx].refs[3];
        if tree_of_cells[cell_idx].refs[3] == 255 {
            return Err(StdError::generic_err("No McBlockExtra"));
        }

        if read_u16(boc, tree_of_cells, cell_idx, 16)? != BLOCK_EXTRA_CELL {
            return Err(StdError::generic_err("not a McBlockExtra"));
        }

        let is_key_block = read_bool(boc, tree_of_cells, cell_idx);

        if is_key_block {
            // config params
            // skip useless data TODO: check tlb for this struct
            // tree_of_cells[cell_idx].cursor += 76
            tree_of_cells[cell_idx].cursor += 8 + 4;
            // readBytes32BitSize(boc, tree_of_cells, cell_idx, 76);
            // bytes32 configAddress =
            read_bytes32_bit_size(boc, tree_of_cells, cell_idx, 256);

            let mut config_params_idx = if tree_of_cells[cell_idx].refs[3] == 255 {
                tree_of_cells[cell_idx].refs[2]
            } else {
                tree_of_cells[cell_idx].refs[3]
            };

            if config_params_idx == 255 {
                return Err(StdError::generic_err("No Config Params"));
            }

            let tx_idxs = parse_dict(boc, tree_of_cells, config_params_idx, 32)?;

            for i in 0..32 {
                if tx_idxs[i] == 255 {
                    if i > 0 {
                        config_params_idx = tx_idxs[i - 1];
                    }
                    break;
                }
            }

            return parse_config_param342(boc, tree_of_cells, config_params_idx);
        }

        Err(StdError::generic_err("is no key block"))
    }

    fn parse_part_validators(
        &self,
        data: &[u8],
        cell_idx: usize,
        cells: &mut [CellData],
        prefix_length: u128,
    ) -> StdResult<ValidatorSet32> {
        let tx_idxs = parse_dict(data, cells, cell_idx, prefix_length)?;

        let mut validators = [ValidatorDescription::default(); 32];
        for i in 0..32 {
            if tx_idxs[i] == 255 {
                break;
            }
            validators[i] = read_validator_description(data, cells, tx_idxs[i])?;
        }

        Ok(validators)
    }

    fn parse_block(
        &self,
        proof_boc: &[u8],
        proof_boc_info: &mut BagOfCellsInfo,
        proof_tree_of_cells: &mut [CellData],
        tx_root_hash: Bytes32,
        transaction: &mut TransactionHeader,
    ) -> StdResult<bool> {
        let proof_root_idx = proof_boc_info.root_idx;

        read_u32(proof_boc, proof_tree_of_cells, proof_root_idx, 32)?;

        // blockInfo^ (pruned)
        // uint256 blockInfoIdx =
        read_cell(proof_tree_of_cells, proof_root_idx);
        // require(check_block_info(proofTreeOfCells, blockInfoIdx, transaction), "lt doesn't belong to block interval");
        // value flow^ (pruned)
        read_cell(proof_tree_of_cells, proof_root_idx);
        // state_update^ (pruned)
        read_cell(proof_tree_of_cells, proof_root_idx);
        let extra_idx = read_cell(proof_tree_of_cells, proof_root_idx);

        parse_block_extra(
            proof_boc,
            proof_tree_of_cells,
            extra_idx,
            tx_root_hash,
            transaction,
        )
    }
}

pub fn read_coins(data: &[u8], cells: &mut [CellData], cell_idx: usize) -> StdResult<Bytes32> {
    let bytes = read_u8(data, cells, cell_idx, 4)?;

    if bytes == 0 {
        return Ok(Bytes32::default());
    }

    Ok(read_bytes32_byte_size(
        data,
        cells,
        cell_idx,
        bytes as usize,
    ))
}

pub fn parse_currency_collection(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
) -> StdResult<Bytes32> {
    let coins = read_coins(data, cells, cell_idx)?;
    let check = read_bool(data, cells, cell_idx);
    if check {
        let dc_idx = read_cell(cells, cell_idx);
        if !cells[dc_idx].special {
            parse_dict(data, cells, dc_idx, 32)?;
        }
    }

    Ok(coins)
}

pub fn read_int(data: &[u8], mut size: usize) -> usize {
    let mut res = 0;
    let mut cursor = 0;
    while size > 0 {
        res = (res << 8) + data[cursor] as usize;
        cursor += 1;
        size -= 1;
    }
    res
}

pub fn read_uint_leq(
    proof_boc: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    n: u128,
) -> StdResult<Uint256> {
    let mut last_one = 0u16;
    let mut l = 1u128;
    let mut found = false;
    for i in 0..32 {
        if (n & l) > 0 {
            last_one = i;
            found = true;
        }
        l <<= 1;
    }

    if !found {
        return Err(StdError::generic_err("not a UintLe"));
    }

    last_one += 1;
    read_uint256(proof_boc, cells, cell_idx, last_one)
}

fn parse_block_extra(
    proof_boc: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    tx_root_hash: Bytes32,
    transaction: &mut TransactionHeader,
) -> StdResult<bool> {
    if 1244919549 != read_u32(proof_boc, cells, cell_idx, 32)? {
        return Err(StdError::generic_err("cell is not extra block info"));
    }

    // in_msg_descr^ (pruned)
    read_cell(cells, cell_idx);
    // out_msg_descr^ (pruned)
    read_cell(cells, cell_idx);
    // account_blocks^
    let acc_idx = read_cell(cells, cell_idx);
    let account_blocks_idx = read_cell(cells, acc_idx);

    let account_idxs = parse_dict(proof_boc, cells, account_blocks_idx, 256)?;

    for i in 0..32 {
        if account_idxs[i] == 255 {
            break;
        }
        // _ (HashmapAugE 256 AccountBlock CurrencyCollection) = ShardAccountBlocks;
        parse_currency_collection(proof_boc, cells, account_idxs[i])?;
        if read_u8(proof_boc, cells, account_idxs[i], 4)? != 5 {
            return Err(StdError::generic_err("is not account block"));
        }

        let address_hash = read_bytes32_byte_size(proof_boc, cells, account_idxs[i], 32);

        if address_hash != transaction.address_hash {
            continue;
        }

        // get transactions of this account
        let tx_idxs = parse_dict(proof_boc, cells, account_idxs[i], 64)?;

        for j in 0..32 {
            if tx_idxs[j] == 255 {
                break;
            }
            if cells[read_cell(cells, tx_idxs[j])].hashes[0] == tx_root_hash {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_validator_description(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
) -> StdResult<ValidatorDescription> {
    let c_type = read_u8(data, cells, cell_idx, 8)?;

    if read_u32(data, cells, cell_idx, 32)? != 0x8e81278a {
        return Err(StdError::generic_err("not a SigPubKey"));
    }

    let pubkey = read_bytes32_bit_size(data, cells, cell_idx, 256);
    let weight = read_u64(data, cells, cell_idx, 64)?;
    let adnl_addr = if c_type == 0x73 {
        read_bytes32_bit_size(data, cells, cell_idx, 256)
    } else {
        Bytes32::default()
    };
    Ok(ValidatorDescription {
        c_type,
        weight,
        adnl_addr,
        pubkey,
        node_id: Bytes32::default(),
    })
}

fn do_parse2(
    data: &[u8],
    prefix: u128,
    cells: &mut [CellData],
    cell_idx: usize,
    n: u128,
    cell_idxs: &mut [usize; 32],
    pruned_cells: &mut [CachedCell; 10],
) -> StdResult<()> {
    let prefix_length;
    let mut pp = prefix;

    // lb0
    if !read_bool(data, cells, cell_idx) {
        // Short label detected
        prefix_length = read_unary_length(data, cells, cell_idx);

        for _ in 0..prefix_length {
            pp = (pp << 1) + read_bit(data, cells, cell_idx) as u128;
        }
    } else {
        // lb1
        if !read_bool(data, cells, cell_idx) {
            // long label detected
            prefix_length = read_u64(data, cells, cell_idx, log2ceil(n))? as u128;
            for _ in 0..prefix_length {
                pp = (pp << 1) + read_bit(data, cells, cell_idx) as u128;
            }
        } else {
            // Same label detected
            let bit = read_bit(data, cells, cell_idx) as u128;
            prefix_length = read_u64(data, cells, cell_idx, log2ceil(n))? as u128;

            for _ in 0..prefix_length {
                pp = (pp << 1) + bit;
            }
        }
    }

    if n - prefix_length == 0 {
        // end
        for i in 0..32 {
            if cell_idxs[i] == 255 {
                cell_idxs[i] = cell_idx;
                break;
            }
        }
        // cell_idxs[pp] = cell_idx;
        // res.set(new BN(pp, 2).toString(32), extractor(slice));
    } else {
        let left_idx = read_cell(cells, cell_idx);
        let right_idx = read_cell(cells, cell_idx);

        // NOTE: Left and right branches are implicitly contain prefixes '0' and '1'
        if left_idx != 255 && !cells[left_idx].special {
            do_parse2(
                data,
                pp << 1,
                cells,
                left_idx,
                n - prefix_length - 1,
                cell_idxs,
                pruned_cells,
            )?;
        } else if cells[left_idx].special {
            let start_idx = cells[left_idx].cursor / 8 + 2;
            let end_idx = start_idx + 32;
            let sdata = CachedCell {
                prefix_length: n - prefix_length - 1,
                hash: data[start_idx..end_idx]
                    .try_into()
                    .map_err(|_| StdError::generic_err("hash is not 32 bits"))?,
            };
            for i in 0..10 {
                if pruned_cells[i].prefix_length == 0 {
                    pruned_cells[i] = sdata;
                    break;
                }
            }
        }
        if right_idx != 255 && !cells[right_idx].special {
            do_parse2(
                data,
                pp << (1 + 1),
                cells,
                right_idx,
                n - prefix_length - 1,
                cell_idxs,
                pruned_cells,
            )?;
        } else if cells[right_idx].special {
            let start_idx = cells[right_idx].cursor / 8 + 2;
            let end_idx = start_idx + 32;

            let sdata = CachedCell {
                prefix_length: n - prefix_length - 1,
                hash: data[start_idx..end_idx]
                    .try_into()
                    .map_err(|_| StdError::generic_err("hash is not 32 bits"))?,
            };

            for i in 0..10 {
                if pruned_cells[i].prefix_length == 0 {
                    pruned_cells[i] = sdata;
                    break;
                }
            }
        }
    }

    Ok(())
}

fn parse_dict2(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    key_size: u128,
) -> StdResult<([usize; 32], [CachedCell; 10])> {
    // pruned_cells
    let mut cell_idxs = [255; 32];
    let mut pruned_cells = [CachedCell::default(); 10];
    do_parse2(
        data,
        0,
        cells,
        cell_idx,
        key_size,
        &mut cell_idxs,
        &mut pruned_cells,
    )?;

    Ok((cell_idxs, pruned_cells))
}

fn parse_config_param342(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
) -> StdResult<ValidatorSet32> {
    // uint256 skipped =
    read_uint256(data, cells, cell_idx, 28)?;
    // uint8 cType =
    read_u8(data, cells, cell_idx, 8)?;

    // uint32 utime_since =
    read_u32(data, cells, cell_idx, 32)?;
    // uint32 utime_until =
    read_u32(data, cells, cell_idx, 32)?;
    // uint16 total =
    read_u16(data, cells, cell_idx, 16)?;
    // uint16 main =
    read_u16(data, cells, cell_idx, 16)?;

    let subcell_idx = read_cell(cells, cell_idx);

    let dict2_idx = read_cell(cells, subcell_idx);
    let (tx_idxs, _) = parse_dict2(data, cells, dict2_idx, 16)?;

    let mut validators = [ValidatorDescription::default(); 32];
    for i in 0..32 {
        if tx_idxs[i] == 255 {
            break;
        }
        validators[i] = read_validator_description(data, cells, tx_idxs[i])?;
    }

    Ok(validators)
}

pub fn check_block_info(
    proof_boc: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    transaction: &mut TransactionHeader,
) -> StdResult<bool> {
    if read_u32(proof_boc, cells, cell_idx, 32)? != BLOCK_INFO_CELL {
        return Err(StdError::generic_err("not a BlockInfo"));
    }

    // // version
    // read_u32(cells, cell_idx, 32);
    // // not_master
    // read_bool(cells, cell_idx);
    // // after_merge
    // read_bool(cells, cell_idx);
    // // before_split
    // read_bool(cells, cell_idx);
    // // after_split
    // read_bool(cells, cell_idx);
    // // want_split
    // read_bool(cells, cell_idx);
    // // want merge
    // read_bool(cells, cell_idx);
    // // key_block
    // read_bool(cells, cell_idx);
    // // vert seqno incer
    // read_bool(cells, cell_idx);
    cells[cell_idx].cursor += 32 + 1 * 8;
    // flags
    if read_u8(proof_boc, cells, cell_idx, 8)? > 1 {
        return Err(StdError::generic_err("data.flags > 1"));
    }
    // seq_no
    // read_u32(cells, cell_idx, 32);
    // vert_seq_no
    // read_u32(cells, cell_idx, 32);
    cells[cell_idx].cursor += 64;
    // shard Ident
    read_u8(proof_boc, cells, cell_idx, 2)?;
    read_uint_leq(proof_boc, cells, cell_idx, 60)?;
    read_u32(proof_boc, cells, cell_idx, 32)?;
    read_u64(proof_boc, cells, cell_idx, 64)?;

    // end shard Ident

    // gen_utime
    read_u32(proof_boc, cells, cell_idx, 32)?;

    let start_lt = read_u64(proof_boc, cells, cell_idx, 64)?;
    let end_lt = read_u64(proof_boc, cells, cell_idx, 64)?;

    Ok(transaction.lt >= start_lt || transaction.lt <= end_lt)
}

pub fn compute_node_id(public_key: Bytes32) -> Bytes32 {
    let mut data = vec![0xc6, 0xb4, 0x13, 0x48];
    data.extend_from_slice(&public_key);
    sha256(&data)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;

    use crate::types::Bytes32;

    #[test]
    fn test_hex_convert() {
        let ret = HexBinary::from_hex("c6b41348").unwrap();
        let ret1 = HexBinary::from([0xc6, 0xb4, 0x13, 0x48]);
        println!("{} {}", ret.to_hex(), ret1.to_hex());

        print!("{:?}", Bytes32::default());
        assert!(2390828938u32 == 0x8e81278a);
    }
}
