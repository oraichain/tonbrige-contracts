export type Uint128 = string;
export type Addr = string;
export type AssetInfo = {
  token: {
    contract_addr: Addr;
  };
} | {
  native_token: {
    denom: string;
  };
};
export interface InstantiateMsg {
  bridge_adapter: string;
  relayer_fee?: Uint128 | null;
  relayer_fee_receiver: Addr;
  relayer_fee_token: AssetInfo;
  swap_router_contract: string;
  token_factory_addr?: Addr | null;
  token_fee_receiver: Addr;
  validator_contract_addr: Addr;
}
export type ExecuteMsg = {
  read_transaction: {
    tx_boc: HexBinary;
    tx_proof: HexBinary;
  };
} | {
  update_mapping_pair: UpdatePairMsg;
} | {
  delete_mapping_pair: DeletePairMsg;
} | {
  bridge_to_ton: BridgeToTonMsg;
} | {
  receive: Cw20ReceiveMsg;
} | {
  update_owner: {
    new_owner: Addr;
  };
} | {
  update_config: {
    bridge_adapter?: string | null;
    relayer_fee?: Uint128 | null;
    relayer_fee_receiver?: Addr | null;
    relayer_fee_token?: AssetInfo | null;
    swap_router_contract?: string | null;
    token_fee?: TokenFee[] | null;
    token_fee_receiver?: Addr | null;
    validator_contract_addr?: Addr | null;
  };
} | {
  register_denom: RegisterDenomMsg;
};
export type HexBinary = string;
export type Binary = string;
export interface UpdatePairMsg {
  denom: string;
  local_asset_info: AssetInfo;
  local_asset_info_decimals: number;
  opcode: HexBinary;
  remote_decimals: number;
  token_origin: number;
}
export interface DeletePairMsg {
  denom: string;
}
export interface BridgeToTonMsg {
  denom: string;
  timeout?: number | null;
  to: string;
}
export interface Cw20ReceiveMsg {
  amount: Uint128;
  msg: Binary;
  sender: string;
}
export interface TokenFee {
  ratio: Ratio;
  token_denom: string;
}
export interface Ratio {
  denominator: number;
  nominator: number;
}
export interface RegisterDenomMsg {
  metadata?: Metadata | null;
  subdenom: string;
}
export interface Metadata {
  base?: string | null;
  denom_units: DenomUnit[];
  description?: string | null;
  display?: string | null;
  name?: string | null;
  symbol?: string | null;
}
export interface DenomUnit {
  aliases: string[];
  denom: string;
  exponent: number;
}
export type QueryMsg = {
  owner: {};
} | {
  config: {};
} | {
  is_tx_processed: {
    tx_hash: HexBinary;
  };
} | {
  channel_state_data: {};
} | {
  token_fee: {
    remote_token_denom: string;
  };
} | {
  pair_mapping: {
    key: string;
  };
} | {
  send_packet_commitment: {
    seq: number;
  };
} | {
  ack_commitment: {
    seq: number;
  };
};
export interface MigrateMsg {}
export type Uint256 = string;
export type Amount = {
  native: Coin;
} | {
  cw20: Cw20Coin;
};
export interface ChannelResponse {
  balances: Amount[];
  total_sent: Amount[];
}
export interface Coin {
  amount: Uint128;
  denom: string;
}
export interface Cw20Coin {
  address: string;
  amount: Uint128;
}
export type RouterController = string;
export interface Config {
  bridge_adapter: string;
  relayer_fee: Uint128;
  relayer_fee_receiver: Addr;
  relayer_fee_token: AssetInfo;
  swap_router_contract: RouterController;
  token_factory_addr?: Addr | null;
  token_fee_receiver: Addr;
  validator_contract_addr: Addr;
}
export type Boolean = boolean;
export type String = string;
export interface PairQuery {
  key: string;
  pair_mapping: MappingMetadata;
}
export interface MappingMetadata {
  asset_info: AssetInfo;
  asset_info_decimals: number;
  opcode: [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
  remote_decimals: number;
  token_origin: number;
}