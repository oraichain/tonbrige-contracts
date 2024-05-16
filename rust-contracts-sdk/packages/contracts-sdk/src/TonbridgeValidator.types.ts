import {Boolean} from "./types";
export interface InstantiateMsg {
  boc?: string | null;
}
export type ExecuteMsg = {
  parse_candidates_root_block: {
    boc: string;
  };
} | {
  reset_validator_set: {
    boc: string;
  };
} | {
  verify_validators: {
    file_hash: string;
    root_hash: string;
    vdata: VdataHex[];
  };
} | {
  read_master_proof: {
    boc: string;
  };
} | {
  read_state_proof: {
    boc: string;
    root_hash: string;
  };
} | {
  parse_shard_proof_path: {
    boc: string;
  };
} | {
  set_verified_block: {
    root_hash: string;
    seq_no: number;
  };
};
export interface VdataHex {
  node_id: string;
  r: string;
  s: string;
}
export type QueryMsg = {
  config: {};
} | {
  get_candidates_for_validators: {};
} | {
  get_validators: {};
} | {
  is_verified_block: {
    root_hash: string;
  };
} | {
  is_signed_by_validator: {
    root_hash: string;
    validator_node_id: string;
  };
};
export interface MigrateMsg {}
export interface ConfigResponse {
  owner?: string | null;
}
export type ArrayOfUserFriendlyValidator = UserFriendlyValidator[];
export interface UserFriendlyValidator {
  adnl_addr: string;
  c_type: number;
  node_id: string;
  pubkey: string;
  weight: number;
}