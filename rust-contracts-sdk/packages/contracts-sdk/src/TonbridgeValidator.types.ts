import {Boolean} from "./types";
export interface InstantiateMsg {}
export type ExecuteMsg = {
  parse_candidates_root_block: {
    boc: string;
  };
} | {
  init_validators: {};
} | {
  set_validator_set: {};
} | {
  verify_validators: {
    file_hash: string;
    root_hash: string;
    vdata: [VdataHex, VdataHex, VdataHex, VdataHex, VdataHex];
  };
} | {
  add_current_block_to_verified_set: {
    root_hash: string;
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