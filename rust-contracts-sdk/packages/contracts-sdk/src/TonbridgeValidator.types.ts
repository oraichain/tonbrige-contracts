import {HexBinary, Boolean} from "./types";
export interface InstantiateMsg {
  boc?: HexBinary | null;
}
export type ExecuteMsg = {
  prepare_new_key_block: {
    keyblock_boc: HexBinary;
  };
} | {
  reset_validator_set: {
    boc: HexBinary;
  };
} | {
  verify_key_block: {
    file_hash: HexBinary;
    root_hash: HexBinary;
    vdata: VdataHex[];
  };
} | {
  verify_masterchain_block_by_validator_signatures: {
    block_boc: HexBinary;
    block_header_proof: HexBinary;
    file_hash: HexBinary;
    vdata: VdataHex[];
  };
} | {
  verify_shard_blocks: {
    mc_block_root_hash: HexBinary;
    shard_proof_links: HexBinary[];
  };
} | {
  set_verified_block: {
    root_hash: HexBinary;
    seq_no: number;
  };
};
export interface VdataHex {
  node_id: HexBinary;
  r: HexBinary;
  s: HexBinary;
}
export type QueryMsg = {
  config: {};
} | {
  get_candidates_for_validators: {
    limit?: number | null;
    order?: number | null;
    start_after?: number | null;
  };
} | {
  get_validators: {
    limit?: number | null;
    order?: number | null;
    start_after?: string | null;
  };
} | {
  is_verified_block: {
    root_hash: HexBinary;
  };
} | {
  is_signed_by_validator: {
    root_hash: HexBinary;
    validator_node_id: HexBinary;
  };
};
export interface MigrateMsg {}
export interface ConfigResponse {
  owner?: string | null;
}
export type ArrayOfUserFriendlyValidator = UserFriendlyValidator[];
export interface UserFriendlyValidator {
  adnl_addr: HexBinary;
  c_type: number;
  node_id: HexBinary;
  pubkey: HexBinary;
  weight: number;
}