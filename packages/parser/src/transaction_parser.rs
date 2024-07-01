use cosmwasm_schema::cw_serde;
use tonlib::cell::{Cell, TonCellError};

use crate::types::BridgePacketDataRaw;

pub trait ITransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError>;
    fn parse_send_packet_timeout_data(&self, cell: &Cell) -> Result<u64, TonCellError>;
}

pub const SEND_PACKET_TIMEOUT_MAGIC_NUMBER: u32 = 0x540CE379; // crc32("src::timeout_send_packet")
pub const RECEIVE_PACKET_MAGIC_NUMBER: u32 = 0x4b9c032d; // crc32("src::receive_packet")

pub fn get_channel_id(channel_num: u16) -> String {
    format!("channel-{:?}", channel_num)
}

#[cw_serde]
#[derive(Default)]
pub struct TransactionParser {}

impl ITransactionParser for TransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError> {
        let mut parser = cell.parser();

        let magic_number = parser.load_u32(32)?;
        if magic_number != RECEIVE_PACKET_MAGIC_NUMBER {
            return Err(TonCellError::cell_parser_error(
                "Not a receive packet from TON to CW",
            ));
        }
        let packet_seq = parser.load_u64(64)?;
        let timeout_timestamp = parser.load_u64(64)?;
        let source_denom = parser.load_address()?;
        let src_sender = parser.load_address()?;
        // assume that the largest channel id is 65536 = 2^16
        let src_channel_num = parser.load_u16(16)?;
        let amount = parser.load_coins()?;

        let mut des_denom: Vec<u8> = vec![];
        let first_ref = cell.reference(0)?;
        if first_ref.references.len() < 4 {
            return Err(TonCellError::cell_parser_error(
                "Packet data does not have 4 references to parse packet data",
            ));
        }
        first_ref.references[0].load_buffer(&mut des_denom)?;
        let mut des_channel: Vec<u8> = vec![];
        first_ref.references[1].load_buffer(&mut des_channel)?;
        let mut des_receiver: Vec<u8> = vec![];
        first_ref.references[2].load_buffer(&mut des_receiver)?;
        let mut orai_address: Vec<u8> = vec![];
        first_ref.references[3].load_buffer(&mut orai_address)?;

        Ok(BridgePacketDataRaw {
            seq: packet_seq,
            timeout_timestamp,
            src_denom: source_denom,
            src_sender,
            src_channel: get_channel_id(src_channel_num).into_bytes(), // FIXME: get src_channel from body data
            amount: amount.to_str_radix(10),
            dest_denom: des_denom,
            dest_channel: des_channel,
            dest_receiver: des_receiver,
            orai_address,
        })
    }

    fn parse_send_packet_timeout_data(&self, cell: &Cell) -> Result<u64, TonCellError> {
        let mut parser = cell.parser();
        let magic_number = parser.load_u32(32)?;
        if magic_number != SEND_PACKET_TIMEOUT_MAGIC_NUMBER {
            return Err(TonCellError::cell_parser_error("Not a send packet timeout"));
        }
        let packet_seq = parser.load_u64(64)?;
        Ok(packet_seq)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{HexBinary, Uint128, Uint256};
    use tonlib::{
        cell::{BagOfCells, Cell},
        responses::MessageType,
    };

    use crate::types::BridgePacketData;

    use super::{ITransactionParser, TransactionParser};

    #[test]
    fn test_address() {
        let test_number = Uint256::from(1_000_000_042u128);
        let hash = test_number.to_be_bytes();
        let ret: [u8; 20] = hash[hash.len() - 20..].try_into().unwrap();
        println!("0x{}", HexBinary::from(&ret).to_hex());
    }

    #[test]
    fn test_load_packet_data_from_tx() {
        let tx_boc = HexBinary::from_hex("b5ee9c720102140100036f0003b57d97d05fcf60328dc70225b5b522bdbe2b1bda0a2e52f0c2b7a3ce0e8dea9172900001513ba0d5d85fc0a773e4754705ea84026db44fbeaaca1e2baf0dd5dedfe39db629d4958734300001513ba0d5d8166828e58000546a6690680102030201e00405008272dcb41d4bf971f06092f6eecdbf898756d673d77735a4e84ae7d12925d9b7c0baf82aaff12d7b49ab7b07f3867ae213de3521afd2baa482b651cc317c41c049b2021504091cee16fc18681bfa11121301b16801ed89e454ebd04155a7ef579cecc7ff77907f2288f16bb339766711298f1f775700365f417f3d80ca371c0896d6d48af6f8ac6f6828b94bc30ade8f383a37aa45ca51cee16fc006175b3800002a27741abb08cd051cb0c0060201dd090a0118af35dc850000000000000000070261ffff800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034abd1a94a20002fbc2afd93dc58010e080043800536affe20d6af471ee32332b9ebfa93e271bd0d924f1e3bc5f0dce4860a07c5100101200b0101200c00c94801b2fa0bf9ec0651b8e044b6b6a457b7c5637b4145ca5e1856f479c1d1bd522e53000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a11cdc586800608235a00002a27741abb0ccd051cb06a993b6d800000000000000040019fe006cbe82fe7b01946e38112dada915edf158ded05172978615bd1e70746f548b94b003cb93f68a17ddadc9e1033a70011995f47a9ca4b7f154529567ed2a85365ea3600001513ba0d5d8766828e58600d01bd4b9c032d000000000000000017de157ec9ee2c00800722ce79faef732792855db51f4a0e589748492ca4cada73bb8a6ab5dd23d034b000a6d5ffc41ad5e8e3dc6466573d7f527c4e37a1b249e3c778be1b9c90c140f8a000017a35294400200e0400100f101100126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478009e4530ac3d09000000000000000000c200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b33304c4952cc000000000004000000000004d7b30c9a07a17122303e6553a62e1d950e281e9004aa667753aa60229513e7b041d0516c").unwrap();

        let tx_cells = BagOfCells::parse(&tx_boc).unwrap();
        let tx_root = tx_cells.single_root().unwrap();
        let transaction = Cell::load_transaction(tx_root, &mut 0, &mut tx_root.parser()).unwrap();
        let tx_parser = TransactionParser::default();

        for out_msg in transaction.out_msgs.into_values() {
            if out_msg.data.is_none() {
                continue;
            }
            let out_msg = out_msg.data.unwrap();
            if out_msg.info.msg_type != MessageType::ExternalOut as u8 {
                continue;
            }

            let cell = out_msg.body.cell_ref.unwrap().0.unwrap().cell;

            let packet_data = tx_parser.parse_packet_data(&cell).unwrap();

            assert_eq!(
                packet_data.to_pretty().unwrap(),
                BridgePacketData {
                    seq: 0,
                    timeout_timestamp: 1719835742000000000,
                    src_sender: "EQAptX_xBrV6OPcZGZXPX9SfE43obJJ48d4vhuckMFA-KKbJ".to_string(),
                    src_denom: "EQA5FnPP13uZPJQq7aj6UHLEukJJZSZW053cU1Wu6R6BpYYB".to_string(),
                    src_channel: "channel-0".to_string(),
                    amount: Uint128::from_str("1000000000000").unwrap(),
                    dest_denom: "".to_string(),
                    dest_channel: "channel-1".to_string(),
                    dest_receiver: "".to_string(),
                    orai_address: "orai1rchnkdpsxzhquu63y6r4j4t57pnc9w8ehdhedx".to_string()
                }
            )
        }
    }
}
