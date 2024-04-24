use cw_storage_plus::Map;
use tonbridge_parser::types::Bytes32;

use cw_controllers::Admin;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");
pub const SIGNED_BLOCKS: Map<(Bytes32, Bytes32), bool> = Map::new("signed_blocks");
