use cosmwasm_std::StdResult;

use crate::msg::Ics20Packet;

pub fn get_key_ics20_ibc_denom(port_id: &str, channel_id: &str, denom: &str) -> String {
    format!("{}/{}/{}", port_id, channel_id, denom)
}

pub fn parse_ibc_wasm_port_id(contract_addr: &str) -> String {
    format!("wasm.{}", contract_addr)
}

pub fn parse_packet_boc_to_ics_20(_packet_boc: &[u8]) -> StdResult<Ics20Packet> {
    // TODO: parse packet boc to ics20 packet
    Ok(Ics20Packet::default())
}
