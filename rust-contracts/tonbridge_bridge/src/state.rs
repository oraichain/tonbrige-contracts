use cw_storage_plus::Map;

use cw_controllers::Admin;
use tonbridge_parser::types::Bytes32;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");

// Store processed txs to prevent replay attack
pub const PROCESSED_TXS: Map<&Bytes32, bool> = Map::new("processed_txs");
