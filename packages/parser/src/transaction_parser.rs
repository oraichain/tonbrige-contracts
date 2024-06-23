use cosmwasm_schema::cw_serde;
use tonlib::cell::{Cell, TonCellError};

use crate::types::BridgePacketDataRaw;

pub trait ITransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError>;
}

#[cw_serde]
#[derive(Default)]
pub struct TransactionParser {}

impl ITransactionParser for TransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError> {
        let mut parser = cell.parser();

        let source_denom = parser.load_address()?;
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
            src_denom: source_denom,
            src_channel: "channel-0".as_bytes().to_vec(), // FIXME: get src_channel from body data
            amount: amount.to_str_radix(10),
            dest_denom: des_denom,
            dest_channel: des_channel,
            dest_receiver: des_receiver,
            orai_address: orai_address,
        })
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
        let tx_boc = HexBinary::from_hex("b5ee9c7241020f010002980003b57c2f3e8d5279ced802ed49fa27fc78194d56eae6cdc21a22cf5cc39774b05f1ed0000000002625a005748504d3d21169b400bf4b45fafc84e0b89be22fc30b54016952e427a6124a600000000023493406673aca10003471c45708010b0c0201e0020401c968004c0b3c62139d1c03b60918dec4768befcc45df7da6a2de6d219a915d73bdf09d0030bcfa3549e73b600bb527e89ff1e065355bab9b3708688b3d730e5dd2c17c7b50e9cb612006319f3a0000000004a62f82cce75942579aee42800000000000000040030151ffff800f7d34e75873470fe40e79d23384bc61e73f2da1d5482d94b2542ea6986994012a9b10b18401070101df05019fe006179f46a93ce76c0176a4fd13fe3c0ca6ab757366e10d1167ae61cbba582f8f6b00e9d61545a0d3728a449b52e821594c643d7f41db8be13e70a4f303234894ce220000000002625a016673aca16006014f800f7d34e75873470fe40e79d23384bc61e73f2da1d5482d94b2542ea6986994012a9b10b18400100704000908090a00126368616e6e656c2d31000000566f726169317263686e6b647073787a687175753633793672346a34743537706e6339773865686468656478008272e17b490aee33d9121cc94f41e2a7182fc52631695ec15d53e6dce10296efa2a828968d90e5706ae641bfc36b017fb5c6574ee8b0b1773d52f2df17946936b214021504090e9cb612186d82fc110d0e009e43758c3bd9f400000000000000008c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc991056c4c882b6000000000000200000000000399a721ca1ff45fa142362f0a8490913b28005e7c14605de003f0c5dfc915c4f841902aac8e9a424d").unwrap();

        let tx_cells = BagOfCells::parse(&tx_boc).unwrap();
        let tx_root = tx_cells.single_root().unwrap();
        let transaction = Cell::load_transaction(tx_root, &mut 0, &mut tx_root.parser()).unwrap();
        let tx_parser = TransactionParser::default();

        for (_, out_msg) in transaction.out_msgs.into_values().enumerate() {
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
                    src_denom: "EQB76ac6w5o4fyBzzpGcJeMPOfltDqpBbKWSoXU0w0ygCYVs".to_string(),
                    src_channel: "channel-0".to_string(),
                    amount: Uint128::from_str("333000000000").unwrap(),
                    dest_denom: "".to_string(),
                    dest_channel: "channel-1".to_string(),
                    dest_receiver: "".to_string(),
                    orai_address: "orai1rchnkdpsxzhquu63y6r4j4t57pnc9w8ehdhedx".to_string()
                }
            )
        }
    }
}
