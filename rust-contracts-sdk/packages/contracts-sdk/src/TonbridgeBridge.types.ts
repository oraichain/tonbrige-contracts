import {HexBinary, Boolean} from "./types";
export interface InstantiateMsg {}
export type ExecuteMsg = {
  read_transaction: {
    block_boc: HexBinary;
    opcode: HexBinary;
    tx_boc: HexBinary;
    validator_contract_addr: string;
  };
} | {
  update_mapping_pair: UpdatePairMsg;
};
export type AssetInfo = {
  token: {
    contract_addr: Addr;
  };
} | {
  native_token: {
    denom: string;
  };
};
export type Addr = string;
export interface UpdatePairMsg {
  denom: string;
  local_asset_info: AssetInfo;
  local_asset_info_decimals: number;
  local_channel_id: string;
  remote_decimals: number;
}
export type QueryMsg = {
  config: {};
} | {
  is_tx_processed: {
    tx_hash: HexBinary;
  };
};
export interface MigrateMsg {}
export interface ConfigResponse {
  owner?: string | null;
}