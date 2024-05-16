import {HexBinary, Boolean} from "./types";
export interface InstantiateMsg {}
export type ExecuteMsg = {
  read_transaction: {
    block_boc: HexBinary;
    opcode: HexBinary;
    ton_token: string;
    tx_boc: HexBinary;
    validator_contract_addr: string;
  };
};
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