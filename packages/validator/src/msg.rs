use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;
use tonbridge_parser::types::VdataHex;

#[cw_serde]
pub struct InstantiateMsg {
    pub boc: Option<HexBinary>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ParseCandidatesRootBlock {
        boc: HexBinary, // in hex form
    },
    ResetValidatorSet {
        boc: HexBinary,
    },
    VerifyValidators {
        root_hash: HexBinary, // in hex form
        file_hash: HexBinary, // in hex form
        vdata: Vec<VdataHex>,
    },
    // commented out because dont use yet
    // AddCurrentBlockToVerifiedSet {
    //     root_hash: String,
    // },
    ReadMasterProof {
        boc: HexBinary, // in hex form
    },
    ReadStateProof {
        boc: HexBinary,       // in hex form
        root_hash: HexBinary, // in hex form
    },
    ParseShardProofPath {
        boc: HexBinary, // in hex form
    },
    SetVerifiedBlock {
        root_hash: HexBinary,
        seq_no: u32,
    },
}

/// We currently take no arguments for migrations
#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},
    #[returns(Vec<UserFriendlyValidator>)]
    GetCandidatesForValidators {
        start_after: Option<u64>,
        limit: Option<u32>,
        order: Option<u8>,
    },
    #[returns(Vec<UserFriendlyValidator>)]
    GetValidators {
        start_after: Option<u64>,
        limit: Option<u32>,
        order: Option<u8>,
    },
    #[returns(bool)]
    IsVerifiedBlock { root_hash: HexBinary }, // in hex form
    #[returns(bool)]
    IsSignedByValidator {
        validator_node_id: HexBinary,
        root_hash: HexBinary,
    },
}

// We define a custom struct for each query response
#[cw_serde]
pub struct ConfigResponse {
    pub owner: Option<String>,
}

#[cw_serde]
pub struct UserFriendlyValidator {
    pub c_type: u8,
    pub weight: u64,
    pub adnl_addr: HexBinary,
    pub pubkey: HexBinary,  // in hex form
    pub node_id: HexBinary, // in hex form
}
