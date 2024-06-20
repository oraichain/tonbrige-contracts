use std::array::TryFromSliceError;

use super::types::Bytes32;
use cosmwasm_std::{HexBinary, StdError};

pub fn to_bytes32(hex_bin: &HexBinary) -> Result<Bytes32, StdError> {
    hex_bin
        .as_slice()
        .try_into()
        .map_err(|err: TryFromSliceError| StdError::generic_err(err.to_string()))
}
