use cosmwasm_schema::{cw_serde, QueryResponses};
use tonbridge_parser::types::VdataHex;

#[cw_serde]
pub struct InstantiateMsg {
    pub boc: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ParseCandidatesRootBlock {
        boc: String, // in hex form
    },
    // SetValidatorSet {},
    ResetValidatorSet {
        boc: String,
    },
    VerifyValidators {
        root_hash: String, // in hex form
        file_hash: String, // in hex form
        vdata: Vec<VdataHex>,
    },
    AddCurrentBlockToVerifiedSet {
        root_hash: String,
    },
    ReadStateProof {
        boc: String,       // in hex form
        root_hash: String, // in hex form
    },
    ParseShardProofPath {
        boc: String, // in hex form
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
    GetCandidatesForValidators {},
    #[returns(Vec<UserFriendlyValidator>)]
    GetValidators {},
    #[returns(bool)]
    IsVerifiedBlock { root_hash: String }, // in hex form
    #[returns(bool)]
    IsSignedByValidator {
        validator_node_id: String,
        root_hash: String,
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
    pub adnl_addr: String,
    pub pubkey: String,  // in hex form
    pub node_id: String, // in hex form
}
