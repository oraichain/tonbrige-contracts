use std::array::TryFromSliceError;

use super::types::{Address, Bytes32, CellData};
use cosmwasm_std::{HexBinary, StdError, StdResult, Uint256};
use sha2::{Digest, Sha256};

const BIT_MASK: [u8; 8] = [
    0b1000_0000,
    0b0100_0000,
    0b0010_0000,
    0b0001_0000,
    0b0000_1000,
    0b0000_0100,
    0b0000_0010,
    0b0000_0001,
];

pub fn to_bytes32(str: &str) -> Result<Bytes32, StdError> {
    HexBinary::from_hex(str)
        .unwrap()
        .as_slice()
        .try_into()
        .map_err(|err: TryFromSliceError| StdError::generic_err(err.to_string()))
}

pub fn read_bit(data: &[u8], cells: &mut [CellData], cell_idx: usize) -> u8 {
    let cursor = cells[cell_idx].cursor >> 3;
    let bytes_start = cells[cell_idx].cursor & 7; // a % b is equivalent to (b - 1) & a
    cells[cell_idx].cursor += 1;
    (data[cursor] << bytes_start) >> 7
}

pub fn read_bool(data: &[u8], cells: &mut [CellData], cell_idx: usize) -> bool {
    read_bit(data, cells, cell_idx) == 1
}

pub fn read_u8(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    mut size: u8,
) -> StdResult<u8> {
    if size > 8 {
        return Err(StdError::generic_err("max size is 8 bits"));
    }
    let mut value = 0;
    while size > 0 {
        value = (value << 1) + read_bit(data, cells, cell_idx);
        size -= 1;
    }

    Ok(value)
}

pub fn read_u16(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    mut size: u8,
) -> StdResult<u16> {
    if size > 16 {
        return Err(StdError::generic_err("max size is 16 bits"));
    }
    let mut value = 0;
    while size > 0 {
        value = (value << 1) + read_bit(data, cells, cell_idx) as u16;
        size -= 1;
    }

    Ok(value)
}

pub fn read_u32(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    mut size: u8,
) -> StdResult<u32> {
    if size > 32 {
        return Err(StdError::generic_err("max size is 32 bits"));
    }
    let mut value = 0;
    while size > 0 {
        value = (value << 1) + read_bit(data, cells, cell_idx) as u32;
        size -= 1;
    }

    Ok(value)
}

pub fn read_u64(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    mut size: u8,
) -> StdResult<u64> {
    if size > 64 {
        return Err(StdError::generic_err("max size is 64 bits"));
    }
    let mut value = 0;
    while size > 0 {
        value = (value << 1) + read_bit(data, cells, cell_idx) as u64;
        size -= 1;
    }

    Ok(value)
}

pub fn read_uint256(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    size: usize,
) -> StdResult<Uint256> {
    if size > 256 {
        return Err(StdError::generic_err("max size is 256 bits"));
    }

    Ok(Uint256::from_be_bytes(read_bytes32_bit_size(
        data,
        cells,
        cell_idx,
        size as usize,
    )))
}

pub fn read_bytes32_bit_size(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    mut size: usize,
) -> Bytes32 {
    let mut value = [0u8; 32]; // 32 bytes = 256 bits
    while size > 0 {
        let bit = read_bit(data, cells, cell_idx);
        if bit != 0 {
            // set bit
            let position = 256 - size;
            value[position >> 3] |= BIT_MASK[position & 7];
        }

        size -= 1;
    }
    value
}

pub fn read_bytes32_byte_size(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    sizeb: usize,
) -> Bytes32 {
    read_bytes32_bit_size(data, cells, cell_idx, sizeb * 8)
}

pub fn read_cell(cells: &mut [CellData], cell_idx: usize) -> usize {
    let idx = cells[cell_idx].refs[cells[cell_idx].cursor_ref as usize];
    cells[cell_idx].cursor_ref += 1;
    idx
}

pub fn read_unary_length(data: &[u8], cells: &mut [CellData], cell_idx: usize) -> u128 {
    // u128 is big enough
    let mut value = 0u128;
    while read_bool(data, cells, cell_idx) {
        value += 1;
    }
    value
}

pub fn log2ceil(x: u128) -> u8 {
    x.ilog2() as u8 + 1
    // let mut check = false;
    // let mut n = 0u128;

    // while x > 1 {
    //     n += 1;

    //     if x & 1 == 1 && !check {
    //         n += 1;
    //         check = true;
    //     }
    //     x >>= 1
    // }

    // if x == 1 && !check {
    //     n += 1;
    // }

    // Uint256::from(n)
}

pub fn do_parse(
    data: &[u8],
    prefix: u128,
    cells: &mut [CellData],
    cell_idx: usize,
    n: u128,
    cell_idxs: &mut [usize; 32],
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
            let bit = read_bit(data, cells, cell_idx);
            prefix_length = read_u64(data, cells, cell_idx, log2ceil(n))? as u128;
            for _ in 0..prefix_length {
                pp = (pp << 1) + bit as u128;
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
            do_parse(
                data,
                pp << 1,
                cells,
                left_idx,
                n - prefix_length - 1,
                cell_idxs,
            )?;
        }
        if right_idx != 255 && !cells[right_idx].special {
            do_parse(
                data,
                pp << (1 + 1),
                cells,
                right_idx,
                n - prefix_length - 1,
                cell_idxs,
            )?;
        }
    }

    Ok(())
}

pub fn parse_dict(
    data: &[u8],
    cells: &mut [CellData],
    cell_idx: usize,
    key_size: u128,
) -> StdResult<[usize; 32]> {
    let mut cell_idxs = [255; 32];

    do_parse(data, 0, cells, cell_idx, key_size, &mut cell_idxs)?;
    Ok(cell_idxs)
}

pub fn sha256(data: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn address(hash: Bytes32) -> StdResult<Address> {
    hash[hash.len() - 20..]
        .try_into()
        .map_err(|_| StdError::generic_err("eth address must have 20 bits"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{HexBinary, Uint256};

    use super::log2ceil;

    #[test]
    fn test_bytes32() {
        let test_number = Uint256::from(100_000_042u128);
        let ret = test_number.to_be_bytes();
        println!("0x{}", HexBinary::from(&ret).to_hex());
    }

    #[test]
    fn test_log2ceil() {
        let test_number = 1_000_000_042u128;
        for i in 0..100 {
            let ret = log2ceil(test_number + i * 10_000_000_000);
            println!("ret {}", ret);
        }
    }
}
