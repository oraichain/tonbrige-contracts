use cosmwasm_std::StdResult;

use crate::msg::Ics20Packet;

pub fn get_key_ics20_ibc_denom(port_id: &str, channel_id: &str, denom: &str) -> String {
    format!("{}/{}/{}", port_id, channel_id, denom)
}

pub fn parse_ibc_wasm_port_id(contract_addr: &str) -> String {
    format!("wasm.{}", contract_addr)
}
