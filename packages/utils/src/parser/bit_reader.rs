use cosmwasm_std::{StdError, StdResult, Uint256};

use crate::types::{Bytes32, CellData};

// memory: mutable, calldata: immutable

pub fn read_bit(data: &[u8], cells: &mut [CellData; 100], cell_idx: usize) -> u8 {
    let cursor = cells[cell_idx].cursor >> 3;
    let bytes_start = cells[cell_idx].cursor - cursor << 3;
    cells[cell_idx].cursor += 1;
    (data[cursor] << bytes_start) >> 7
}

pub fn read_bool(data: &[u8], cells: &mut [CellData; 100], cell_idx: usize) -> bool {
    read_bit(data, cells, cell_idx) == 1
}

pub fn read_u8(
    data: &[u8],
    cells: &mut [CellData; 100],
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
    cells: &mut [CellData; 100],
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
    cells: &mut [CellData; 100],
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
    cells: &mut [CellData; 100],
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
    cells: &mut [CellData; 100],
    cell_idx: usize,
    mut size: u16,
) -> StdResult<Uint256> {
    if size > 256 {
        return Err(StdError::generic_err("max size is 256 bits"));
    }
    let mut value = Uint256::zero();
    while size > 0 {
        value = (value << 1) + Uint256::from(read_bit(data, cells, cell_idx));
        size -= 1;
    }

    Ok(value)
}

pub fn read_bytes32_bit_size(
    data: &[u8],
    cells: &mut [CellData; 100],
    cell_idx: usize,
    mut size: Uint256,
) -> Bytes32 {
    let mut value = Uint256::zero();
    while !size.is_zero() {
        value = (value << 1) + Uint256::from(read_bit(data, cells, cell_idx));
        size -= Uint256::one();
    }
    value.to_be_bytes()
}

// function readBytes32ByteSize(
//     bytes calldata data,
//     CellData[100] memory cells,
//     uint256 cellIdx,
//     uint256 sizeb
// ) public pure returns (bytes32 buffer) {
//     uint256 size = sizeb * 8;
//     uint256 value = 0;
//     while (size > 0) {
//         value = (value << 1) + readBit(data, cells, cellIdx);
//         size--;
//     }
//     buffer = bytes32(value);
//     return buffer;
// }

// function readCell(
//     CellData[100] memory cells,
//     uint256 cellIdx
// ) public pure returns (uint256 idx) {
//     idx = cells[cellIdx].refs[cells[cellIdx].cursorRef];
//     cells[cellIdx].cursorRef++;
//     return idx;
// }

// function readUnaryLength(
//     bytes calldata data,
//     CellData[100] memory cells,
//     uint256 cellIdx
// ) public pure returns (uint256 value) {
//     value = 0;
//     while (readBool(data, cells, cellIdx)) {
//         value++;
//     }
//     return value;
// }

// function log2Ceil(uint256 x) public pure returns (uint256 n) {
//     bool check = false;

//     for (n = 0; x > 1; x >>= 1) {
//         n += 1;

//         if (x & 1 == 1 && !check) {
//             n += 1;
//             check = true;
//         }
//     }

//     if (x == 1 && !check) {
//         n += 1;
//     }

//     return n;
// }

// function parseDict(
//     bytes calldata data,
//     CellData[100] memory cells,
//     uint256 cellIdx,
//     uint256 keySize
// ) public view returns (uint256[32] memory cellIdxs) {
//     for (uint256 i = 0; i < 32; i++) {
//         cellIdxs[i] = 255;
//     }
//     doParse(data, 0, cells, cellIdx, keySize, cellIdxs);
//     return cellIdxs;
// }

// function doParse(
//     bytes calldata data,
//     uint256 prefix,
//     CellData[100] memory cells,
//     uint256 cellIdx,
//     uint256 n,
//     uint256[32] memory cellIdxs
// ) public view {
//     uint256 prefixLength = 0;
//     uint256 pp = prefix;

//     // lb0
//     if (!readBool(data, cells, cellIdx)) {
//         // Short label detected
//         prefixLength = readUnaryLength(data, cells, cellIdx);

//         for (uint256 i = 0; i < prefixLength; i++) {
//             pp = (pp << 1) + readBit(data, cells, cellIdx);
//         }
//     } else {
//         // lb1
//         if (!readBool(data, cells, cellIdx)) {
//             // long label detected
//             prefixLength = readUint64(data, cells, cellIdx, uint8(log2Ceil(n)));
//             for (uint256 i = 0; i < prefixLength; i++) {
//                 pp = (pp << 1) + readBit(data, cells, cellIdx);
//             }
//         } else {
//             // Same label detected
//             uint256 bit = readBit(data, cells, cellIdx);
//             prefixLength = readUint64(data, cells, cellIdx, uint8(log2Ceil(n)));
//             for (uint256 i = 0; i < prefixLength; i++) {
//                 pp = (pp << 1) + bit;
//             }
//         }
//     }

//     if (n - prefixLength == 0) {
//         // end
//         for (uint256 i = 0; i < 32; i++) {
//             if (cellIdxs[i] == 255) {
//                 cellIdxs[i] = cellIdx;
//                 break;
//             }
//         }
//         // cellIdxs[pp] = cellIdx;
//         // res.set(new BN(pp, 2).toString(32), extractor(slice));
//     } else {
//         uint256 leftIdx = readCell(cells, cellIdx);
//         uint256 rightIdx = readCell(cells, cellIdx);
//         // NOTE: Left and right branches are implicitly contain prefixes '0' and '1'
//         if (leftIdx != 255 && !cells[leftIdx].special) {
//             doParse(
//                 data,
//                 pp << 1,
//                 cells,
//                 leftIdx,
//                 n - prefixLength - 1,
//                 cellIdxs
//             );
//         }
//         if (rightIdx != 255 && !cells[rightIdx].special) {
//             doParse(
//                 data,
//                 pp << (1 + 1),
//                 cells,
//                 rightIdx,
//                 n - prefixLength - 1,
//                 cellIdxs
//             );
//         }
//     }
// }
