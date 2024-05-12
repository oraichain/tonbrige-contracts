use cw_storage_plus::{Item, Map};

use cw_controllers::Admin;
use tonbridge_parser::types::{Bytes32, VerifiedBlockInfo};

use crate::validator::Validator;

/// Owner admin
pub const OWNER: Admin = Admin::new("owner");
pub const SIGNED_BLOCKS: Map<&[u8], bool> = Map::new("signed_blocks");
pub const VERIFIED_BLOCKS: Map<&Bytes32, VerifiedBlockInfo> = Map::new("verified_blocks");

pub const VALIDATOR: Item<Validator> = Item::new("validator");
