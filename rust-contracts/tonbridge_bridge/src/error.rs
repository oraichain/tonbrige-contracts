use cosmwasm_std::{ConversionOverflowError, OverflowError, StdError};
use cw_controllers::AdminError;
use cw_utils::PaymentError;
use thiserror::Error;
use tonlib::cell::TonCellError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    TonCellError(#[from] TonCellError),

    #[error("{0}")]
    AdminError(#[from] AdminError),

    #[error("{0}")]
    Overflow(#[from] OverflowError),

    #[error("{0}")]
    Payment(#[from] PaymentError),

    #[error("{0}")]
    ConversionOverflowError(#[from] ConversionOverflowError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Didn't send any funds")]
    NoFunds {},

    #[error("Invalid funds")]
    InvalidFund {},
}
