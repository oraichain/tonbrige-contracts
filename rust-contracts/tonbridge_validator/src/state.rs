use cw_storage_plus::Map;

use cw_controllers::Admin;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");
pub const SIGNED_BLOCKS: Map<&[u8], bool> = Map::new("signed_blocks");
