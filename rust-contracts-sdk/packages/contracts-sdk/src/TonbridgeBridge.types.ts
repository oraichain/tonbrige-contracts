import {Boolean} from "./types";
export interface InstantiateMsg {}
export type ExecuteMsg = {
  read_transaction: {
    block_boc: string;
    opcode: string;
    ton_token: string;
    tx_boc: string;
    validator_contract_addr: string;
  };
};
export type QueryMsg = {
  config: {};
} | {
  is_tx_processed: {
    tx_hash: string;
  };
};
export interface MigrateMsg {}
export interface ConfigResponse {
  owner?: string | null;
}