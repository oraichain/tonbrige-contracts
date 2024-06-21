use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use cw_controllers::Admin;
use tonbridge_bridge::state::{ChannelState, MappingMetadata};
use tonbridge_parser::types::Bytes32;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");

// Store processed txs to prevent replay attack
pub const PROCESSED_TXS: Map<&Bytes32, bool> = Map::new("processed_txs");

pub const TOKEN_FEE: Map<&str, Ratio> = Map::new("token_fee");

// relayer fee. This fee depends on the network type, not token type
// decimals of relayer fee should always be 10^6 because we use ORAI as relayer fee
pub const RELAYER_FEE: Map<&str, Uint128> = Map::new("relayer_fee");

pub const CONFIG: Item<Config> = Item::new("config");

pub const SEND_PACKET: Map<u64, SendPacket> = Map::new("send_packet");

pub const LAST_PACKET_SEQ: Item<u64> = Item::new("last_packet_seq");

// =============================== Reference from: https://github.com/oraichain/ibc-bridge-wasm.git
/// This channel state is used when a REMOTE chain initiates ibc transfer to LOCAL chain
/// LOCAL chain is the chain hosting this smart contract.
pub const REMOTE_INITIATED_CHANNEL_STATE: Map<(&str, &str), ChannelState> =
    Map::new("remote_initiated_channel_state");

// MappingMetadataIndexex structs keeps a list of indexers
pub struct MappingMetadataIndexex<'a> {
    // token.identifier
    pub asset_info: MultiIndex<'a, String, MappingMetadata, String>,
}

// IndexList is just boilerplate code for fetching a struct's indexes
impl<'a> IndexList<MappingMetadata> for MappingMetadataIndexex<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<MappingMetadata>> + '_> {
        let v: Vec<&dyn Index<MappingMetadata>> = vec![&self.asset_info];
        Box::new(v.into_iter())
    }
}

pub fn ics20_denoms<'a>() -> IndexedMap<'a, &'a str, MappingMetadata, MappingMetadataIndexex<'a>> {
    let indexes = MappingMetadataIndexex {
        asset_info: MultiIndex::new(
            |_k, d| d.asset_info.to_string(),
            "ton_ics20_mapping_namespace",
            "asset__info",
        ),
    };
    IndexedMap::new("ics20_mapping_namespace", indexes)
}

#[cw_serde]
pub struct TokenFee {
    pub token_denom: String,
    pub ratio: Ratio,
}

#[cw_serde]
pub struct RelayerFee {
    pub prefix: String,
    pub fee: Uint128,
}

#[cw_serde]
pub struct Ratio {
    pub nominator: u64,
    pub denominator: u64,
}

#[cw_serde]
pub struct Config {
    pub fee_denom: String,
    pub token_fee_receiver: Addr,
    pub relayer_fee_receiver: Addr,
}

#[cw_serde]
pub struct SendPacket {
    pub sequence: u64,
    pub to: String,
    pub denom: String,
    pub amount: Uint128,
    pub crc_src: u32,
}
