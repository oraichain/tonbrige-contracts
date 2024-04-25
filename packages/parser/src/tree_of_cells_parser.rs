use cosmwasm_std::{StdError, StdResult};

use super::{
    bit_reader::{read_u16, read_u8, read_uint256, sha256},
    block_parser::read_int,
    types::{BagOfCellsInfo, Bytes32, Bytes4, CellData, CellSerializationInfo},
};

pub const EMPTY_HASH: Bytes32 = [0; 32];
pub const BOC_IDX: Bytes4 = [0x68, 0xff, 0x65, 0xf3];
pub const BOC_IDX_CRC32C: Bytes4 = [0xac, 0xc3, 0xa7, 0x28];
pub const BOC_GENERIC: Bytes4 = [0xb5, 0xee, 0x9c, 0x72];
pub const ORDINARY_CELL: u8 = 255;
pub const PRUNNED_BRANCH_CELL: u8 = 1;
pub const LIBRARY_CELL: u8 = 2;
pub const MERKLE_PROOF_CELL: u8 = 3;
pub const MERKLE_UPDATE_CELL: u8 = 4;

pub trait ITreeOfCellsParser {
    fn parse_serialized_header(&self, boc: &[u8]) -> StdResult<BagOfCellsInfo>;
    fn get_tree_of_cells(&self, boc: &[u8], info: &mut BagOfCellsInfo) -> StdResult<Vec<CellData>>;
}

#[derive(Default)]
pub struct TreeOfCellsParser {}

impl ITreeOfCellsParser for TreeOfCellsParser {
    fn parse_serialized_header(&self, boc: &[u8]) -> StdResult<BagOfCellsInfo> {
        let mut sz = boc.len();
        let mut ptr = 0;
        let mut header = BagOfCellsInfo::default();

        header.magic = boc[0..4]
            .try_into()
            .map_err(|_| StdError::generic_err("Not enough bytes"))?;

        if header.magic != BOC_GENERIC && header.magic != BOC_IDX && header.magic != BOC_IDX_CRC32C
        {
            return Err(StdError::generic_err("wrong boc type"));
        }

        let flags_byte = boc[4];

        if header.magic == BOC_GENERIC {
            header.has_index = (flags_byte >> 7) % 2 == 1;
            header.has_crc32c = (flags_byte >> 6) % 2 == 1;
            header.has_cache_bits = (flags_byte >> 5) % 2 == 1;
        } else {
            header.has_index = true;
            header.has_crc32c = header.magic == BOC_IDX_CRC32C;
        }

        if header.has_cache_bits && !header.has_index {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.ref_byte_size = flags_byte as usize & 7;
        if header.ref_byte_size > 4 || header.ref_byte_size < 1 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }
        if sz < 6 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.offset_byte_size = boc[5] as usize;
        if header.offset_byte_size > 8 || header.offset_byte_size < 1 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.roots_offset = 6 + 3 * header.ref_byte_size + header.offset_byte_size;
        ptr += 6;
        sz -= 6;
        if sz < header.ref_byte_size {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.cell_count = read_int(&boc[ptr..], header.ref_byte_size);
        if header.cell_count <= 0 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }
        if sz < 2 * header.ref_byte_size {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.root_count = read_int(&boc[ptr + header.ref_byte_size..], header.ref_byte_size);
        if header.root_count == 0 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.index_offset = header.roots_offset;
        if header.magic == BOC_GENERIC {
            header.index_offset += header.root_count * header.ref_byte_size;
            header.has_roots = true;
        } else if header.root_count != 1 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }
        header.data_offset = header.index_offset;
        if header.has_index {
            header.data_offset += header.cell_count * header.offset_byte_size;
        }
        if sz < 3 * header.ref_byte_size {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.absent_count =
            read_int(&boc[ptr + 2 * header.ref_byte_size..], header.ref_byte_size);

        if header.absent_count > header.cell_count {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }
        if sz < 3 * header.ref_byte_size + header.offset_byte_size {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.data_size = read_int(
            &boc[ptr + 3 * header.ref_byte_size..],
            header.offset_byte_size,
        );
        if header.data_size > header.cell_count << 32 {
            return Err(StdError::generic_err("bag-of-cells: invalid header"));
        }

        header.total_size =
            header.data_offset + header.data_size + (if header.has_crc32c { 4 } else { 0 });

        header.root_idx =
            header.cell_count - read_int(&boc[header.roots_offset..], header.ref_byte_size) - 1;

        Ok(header)
    }

    fn get_tree_of_cells(&self, boc: &[u8], info: &mut BagOfCellsInfo) -> StdResult<Vec<CellData>> {
        let custom_index = get_indexes(boc, info)?;

        let cells_slice = &boc[info.data_offset..info.data_offset + info.data_size];
        let mut cells = vec![];

        for i in 0..info.cell_count {
            let mut cell = deserialize_cell(
                info.cell_count - 1 - i,
                cells_slice,
                &custom_index,
                info.ref_byte_size,
                info.cell_count,
            )?;
            cell.cursor += info.data_offset * 8;
            cells.push(cell);
        }
        calc_hashes_for_toc(boc, info, &mut cells)?;
        Ok(cells)
    }
}

fn get_indexes(boc: &[u8], info: &mut BagOfCellsInfo) -> StdResult<Vec<usize>> {
    // require(!info.has_index, "has index logic has not realised");
    // custom_index
    let mut cells_slice_for_indexes = &boc[info.data_offset..info.data_offset + info.data_size];

    let mut custom_index = vec![];
    for i in 0..info.cell_count {
        let cell_info: CellSerializationInfo =
            init_cell_serialization_info(cells_slice_for_indexes, info.ref_byte_size)?;
        cells_slice_for_indexes = &cells_slice_for_indexes[cell_info.end_offset..];

        custom_index.push(cell_info.end_offset);
        if i > 0 {
            custom_index[i] += custom_index[i - 1]
        };
    }

    Ok(custom_index)
}

fn init_cell_serialization_info(
    data: &[u8],
    ref_byte_size: usize,
) -> StdResult<CellSerializationInfo> {
    if data.len() < 2 {
        return Err(StdError::generic_err("Not enough bytes"));
    }

    let mut cell_info = CellSerializationInfo::default();

    let d1 = data[0];
    let d2 = data[1];
    cell_info.d1 = d1;
    cell_info.d2 = d2;
    cell_info.refs_cnt = (d1 & 7) as usize;
    cell_info.level_mask = (d1 >> 5) as u32;
    cell_info.special = (d1 & 8) != 0;

    cell_info.with_hashes = (d1 & 16) != 0;

    if cell_info.refs_cnt > 4 {
        if cell_info.refs_cnt != 7 || !cell_info.with_hashes {
            return Err(StdError::generic_err("Invalid first byte"));
        }

        cell_info.refs_cnt = 0;
        return Err(StdError::generic_err("TODO: absent cells"));
    }

    cell_info.hashes_offset = 2;
    let n = count_setbits(cell_info.level_mask) + 1;
    cell_info.depth_offset =
        cell_info.hashes_offset + if cell_info.with_hashes { n * 32 } else { 0 };
    cell_info.data_offset = cell_info.depth_offset + if cell_info.with_hashes { n * 2 } else { 0 };
    cell_info.data_len = (d2 >> 1) as usize + (d2 & 1) as usize;
    cell_info.data_with_bits = (d2 & 1) != 0;
    cell_info.refs_offset = cell_info.data_offset + cell_info.data_len;
    cell_info.end_offset = cell_info.refs_offset + cell_info.refs_cnt * ref_byte_size;

    if data.len() < cell_info.end_offset {
        return Err(StdError::generic_err("Not enough bytes"));
    }

    Ok(cell_info)
}

// instead of get_hashes_count()
fn count_setbits(mut n: u32) -> usize {
    let mut cnt = 0;
    while n > 0 {
        cnt += n & 1;
        n = n >> 1;
    }
    cnt as usize
}

fn deserialize_cell(
    idx: usize,
    cells_slice: &[u8],
    custom_index: &[usize],
    ref_byte_size: usize,
    cell_count: usize,
) -> StdResult<CellData> {
    let cell_slice = get_cell_slice(idx, cells_slice, custom_index);

    let mut refs = [255; 4];

    let cell_info: CellSerializationInfo = init_cell_serialization_info(cell_slice, ref_byte_size)?;

    if cell_info.end_offset != cell_slice.len() {
        return Err(StdError::generic_err("unused space in cell"));
    }

    for k in 0..cell_info.refs_cnt {
        let ref_idx = read_int(
            &cell_slice[cell_info.refs_offset + k * ref_byte_size..],
            ref_byte_size,
        );
        if ref_idx <= idx {
            return Err(StdError::generic_err("bag-of-cells error"));
        }
        if ref_idx >= cell_count {
            return Err(StdError::generic_err("refIndex is bigger cell count"));
        }
        refs[k] = cell_count - ref_idx - 1;
    }

    let mut cell = create_data_cell(refs, &cell_info);
    cell.cursor = (cell_info.data_offset + if idx == 0 { 0 } else { custom_index[idx - 1] }) * 8;

    cell.level_mask = cell_info.level_mask;
    Ok(cell)
}

fn get_cell_slice<'a>(idx: usize, cells_slice: &'a [u8], custom_index: &'a [usize]) -> &'a [u8] {
    let offs = if idx == 0 { 0 } else { custom_index[idx - 1] };
    let offs_end = custom_index[idx];
    &cells_slice[offs..offs_end]
}

fn create_data_cell(refs: [usize; 4], cell_info: &CellSerializationInfo) -> CellData {
    let mut cell = CellData::default();
    cell.refs = refs;
    cell.special = cell_info.special;
    cell.cursor_ref = 0;
    cell
}

fn calc_hashes_for_toc(
    boc: &[u8],
    info: &mut BagOfCellsInfo,
    cells: &mut [CellData],
) -> StdResult<()> {
    let mut idx;
    let cells_slice = &boc[info.data_offset..info.data_offset + info.data_size];
    let custom_index = get_indexes(boc, info)?;

    for i in 0..info.cell_count {
        idx = info.cell_count - 1 - i;
        let cell_slice = get_cell_slice(idx, cells_slice, &custom_index);

        let mut cell_info = init_cell_serialization_info(cell_slice, info.ref_byte_size)?;

        cells[i].cell_type = ORDINARY_CELL;

        if cells[i].special {
            cells[i].cell_type = read_u8(boc, cells, i, 8)?;
            cells[i].cursor -= 8;
        }

        calc_hash_for_refs(boc, &mut cell_info, cells, i, cell_slice)?;
    }

    Ok(())
}

fn get_hashes_count(mask: u32) -> u8 {
    get_hashes_count_from_mask(mask & 7)
}

fn get_hashes_count_from_mask(mut mask: u32) -> u8 {
    let mut n = 0u8;

    for _ in 0..3 {
        n += (mask & 1) as u8;
        mask = mask >> 1;
    }
    n + 1
}

fn get_level_from_mask(mut mask: u32) -> u8 {
    for i in 0..=3 {
        if mask == 0 {
            return i;
        }
        mask = mask >> 1;
    }
    3
}

fn get_level(mask: u32) -> u8 {
    get_level_from_mask(mask & 7)
}

fn is_level_significant(level: u8, mask: u32) -> bool {
    (level == 0) || ((mask >> (level - 1)) % 2 != 0)
}

fn get_depth(
    data: &[u8],
    level: u8,
    // uint32 mask,
    // uint256 cell_type,
    cells: &mut [CellData],
    cell_idx: usize,
) -> StdResult<u16> {
    let mut hash_i = get_hashes_count_from_mask(apply_level_mask(level, cells[cell_idx].level_mask))
        as usize
        - 1;

    if cells[cell_idx].cell_type == PRUNNED_BRANCH_CELL {
        let this_hash_i = get_hashes_count(cells[cell_idx].level_mask) as usize - 1;
        if hash_i != this_hash_i {
            let cursor = 16 + this_hash_i * 32 * 8 + hash_i * 2 * 8;
            cells[cell_idx].cursor += cursor;

            let child_depth = read_u16(data, cells, cell_idx, 16)?;

            cells[cell_idx].cursor -= cursor + 16;

            return Ok(child_depth);
        }
        hash_i = 0;
    }

    Ok(cells[cell_idx].depth[hash_i])
}

fn apply_level_mask(level: u8, level_mask: u32) -> u32 {
    level_mask & ((1 << level) - 1)
}

fn calc_hash_for_refs(
    data: &[u8],
    cell_info: &mut CellSerializationInfo,
    cells: &mut [CellData],
    i: usize,
    cell_slice: &[u8],
) -> StdResult<()> {
    if cells[i].cell_type == PRUNNED_BRANCH_CELL {
        cells[i].level_mask = cell_slice[3] as u32;
        cell_info.level_mask = cell_slice[3] as u32;
    }

    let hash_i_offset = get_hashes_count(cell_info.level_mask) as usize
        - if cells[i].cell_type == PRUNNED_BRANCH_CELL {
            1
        } else {
            get_hashes_count(cell_info.level_mask) as usize
        };
    let mut hash_i = 0;

    let level = get_level(cell_info.level_mask);

    for level_i in 0..=level {
        if !is_level_significant(level_i, cell_info.level_mask) {
            continue;
        }

        if hash_i < hash_i_offset {
            hash_i += 1;
            continue;
        }

        let mut _hash = vec![];
        {
            if hash_i == hash_i_offset {
                // uint32 new_level_mask = apply_level_mask(level_i);
                if hash_i != 0 && cells[i].cell_type != PRUNNED_BRANCH_CELL {
                    return Err(StdError::generic_err("Cannot deserialize cell"));
                }

                {
                    let mut refs_count = 0;
                    for t in 0..4 {
                        if cells[i].refs[t] == 255 {
                            break;
                        }
                        refs_count += 1;
                    }

                    let new_level_mask = apply_level_mask(level_i, cells[i].level_mask);
                    // uint8 new_d1 =
                    let d1 =
                        refs_count + (if cells[i].special { 8 } else { 0 }) + new_level_mask * 32;
                    _hash = vec![d1 as u8];
                    _hash.extend_from_slice(&cell_slice[1..cell_info.refs_offset]);
                }
            } else {
                if level_i == 0 || cells[i].cell_type == PRUNNED_BRANCH_CELL {
                    return Err(StdError::generic_err("Cannot deserialize cell 2"));
                }

                _hash.extend_from_slice(&cells[i].hashes[hash_i - hash_i_offset - 1]);
            }
        }

        // uint8 dest_i = hash_i - hash_i_offset;
        if cells[i].refs[0] != 255 {
            for j in 0..4 {
                if cells[i].refs[j] == 255 {
                    break;
                }
                _hash.extend_from_slice(
                    &get_depth(data, level_i, cells, cells[i].refs[j])?.to_be_bytes(),
                );

                if get_depth(data, level_i, cells, cells[i].refs[j])?
                    > cells[i].depth[hash_i - hash_i_offset]
                {
                    cells[i].depth[hash_i - hash_i_offset] =
                        get_depth(data, level_i, cells, cells[i].refs[j])?;
                }
            }

            cells[i].depth[hash_i - hash_i_offset] += 1;

            for j in 0..4 {
                if cells[i].refs[j] == 255 {
                    break;
                }

                _hash.extend_from_slice(&get_hash(data, level_i, cells, cells[i].refs[j])?);
            }

            cells[i].hashes[hash_i - hash_i_offset] = sha256(&_hash)?;
        } else {
            cells[i].hashes[hash_i - hash_i_offset] = sha256(&_hash)?;
        }

        hash_i += 1;
    }

    Ok(())
}

fn get_hash(
    data: &[u8],
    level: u8,
    // uint32 level_mask,
    // uint256 cell_type,
    cells: &mut [CellData],
    cell_idx: usize,
) -> StdResult<Bytes32> {
    let mut hash_i =
        get_hashes_count_from_mask(apply_level_mask(level, cells[cell_idx].level_mask)) - 1;

    if cells[cell_idx].cell_type == PRUNNED_BRANCH_CELL {
        let this_hash_i = get_hashes_count(cells[cell_idx].level_mask) - 1;
        if hash_i != this_hash_i {
            let cursor = 16 + (hash_i as usize) * 2 * 8;
            cells[cell_idx].cursor += cursor;
            let hash_num = read_uint256(data, cells, cell_idx, 256)?;
            cells[cell_idx].cursor -= cursor + 256;

            return Ok(hash_num.to_be_bytes());
        }
        hash_i = 0;
    }
    Ok(cells[cell_idx].hashes[hash_i as usize])
}

#[cfg(test)]
mod tests {

    fn increase(mut i: u8) -> u8 {
        i += 1;
        i
    }

    #[test]
    fn test_mut() {
        let i = 10;
        let j = increase(i);
        println!("{} {}", i, j);
    }
}
