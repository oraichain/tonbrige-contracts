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
} | {
  bridge_to_ton: BridgeToTonMsg;
} | {
  receive: Cw20ReceiveMsg;
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
export type Uint128 = string;
export type Binary = string;
export interface UpdatePairMsg {
  denom: string;
  local_asset_info: AssetInfo;
  local_asset_info_decimals: number;
  local_channel_id: string;
  remote_decimals: number;
}
export interface BridgeToTonMsg {
  boc: HexBinary;
}
export interface Cw20ReceiveMsg {
  amount: Uint128;
  msg: Binary;
  sender: string;
}
export type QueryMsg = {
  config: {};
} | {
  is_tx_processed: {
    tx_hash: HexBinary;
  };
} | {
  channel_state_data: {
    channel_id: string;
  };
};
export interface MigrateMsg {}
export type Amount = {
  native: Coin;
} | {
  cw20: Cw20CoinVerified;
};
export interface ChannelResponse {
  balances: Amount[];
  total_sent: Amount[];
}
export interface Coin {
  amount: Uint128;
  denom: string;
}
export interface Cw20CoinVerified {
  address: Addr;
  amount: Uint128;
}
export interface ConfigResponse {
  owner?: string | null;
}