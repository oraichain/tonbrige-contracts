import {HexBinary, Boolean} from "./types";
export interface InstantiateMsg {
  boc?: HexBinary | null;
}
export type ExecuteMsg = {
  parse_candidates_root_block: {
    boc: HexBinary;
  };
} | {
  reset_validator_set: {
    boc: HexBinary;
  };
} | {
  verify_validators: {
    file_hash: HexBinary;
    root_hash: HexBinary;
    vdata: VdataHex[];
  };
} | {
  read_master_proof: {
    boc: HexBinary;
  };
} | {
  read_state_proof: {
    boc: HexBinary;
    root_hash: HexBinary;
  };
} | {
  parse_shard_proof_path: {
    boc: HexBinary;
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
  get_candidates_for_validators: {};
} | {
  get_validators: {};
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