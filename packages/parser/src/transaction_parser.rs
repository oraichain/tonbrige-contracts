use cosmwasm_schema::cw_serde;
use cosmwasm_std::CanonicalAddr;
use tonlib::cell::{Cell, CellParser, TonCellError};

use crate::types::{AckPacket, BridgePacketDataRaw, Status};

pub trait ITransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError>;
    fn parse_ack_data(&self, cell: &Cell) -> Result<AckPacket, TonCellError>;
    fn load_address(parser: &mut CellParser) -> Result<Option<CanonicalAddr>, TonCellError>;
}

pub const RECEIVE_PACKET_MAGIC_NUMBER: u32 = 0xa64c12a3; // crc32("op::send_to_cosmos")
pub const SEND_TO_TON_MAGIC_NUMBER: u32 = 0xae89be5b; // crc32("op::send_to_ton")

#[cw_serde]
#[derive(Default)]
pub struct TransactionParser {}

impl ITransactionParser for TransactionParser {
    fn load_address(parser: &mut CellParser) -> Result<Option<CanonicalAddr>, TonCellError> {
        let num_bytes = parser.load_u8(8)?;
        if num_bytes == 0 {
            Ok(None)
        } else {
            Ok(Some(CanonicalAddr::from(
                parser.load_bytes(num_bytes as usize)?,
            )))
        }
    }

    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError> {
        let mut parser = cell.parser();

        let magic_number = parser.load_u32(32)?;
        if magic_number != RECEIVE_PACKET_MAGIC_NUMBER {
            return Err(TonCellError::cell_parser_error(
                "Not a receive packet from TON to CW",
            ));
        }
        let packet_seq = parser.load_u64(64)?;
        let token_origin = parser.load_u32(32)?;
        let amount = parser.load_u128(128)?;
        let timeout_timestamp = parser.load_u64(64)?;
        let receiver = TransactionParser::load_address(&mut parser)?;
        if receiver.is_none() {
            return Err(TonCellError::cell_parser_error(
                "receiver not contain in packet data",
            ));
        }

        let source_denom = parser.load_address()?;

        if cell.references.is_empty() {
            return Err(TonCellError::cell_parser_error(
                "Packet data does not have 1 references to parse packet data",
            ));
        }

        let src_sender = cell.references[0].parser().load_address()?;

        let memo = if cell.references.len() > 1 {
            Some(cell.references[1].as_ref().clone())
        } else {
            None
        };

        Ok(BridgePacketDataRaw {
            seq: packet_seq,
            token_origin,
            timeout_timestamp,
            src_denom: source_denom,
            src_sender,
            amount,
            receiver: receiver.unwrap(),
            memo,
        })
    }

    fn parse_ack_data(&self, cell: &Cell) -> Result<AckPacket, TonCellError> {
        let mut parser = cell.parser();
        let magic_number = parser.load_u32(32)?;
        if magic_number != SEND_TO_TON_MAGIC_NUMBER {
            return Err(TonCellError::cell_parser_error("Not a ack"));
        }
        let packet_seq = parser.load_u64(64)?;
        let status = Status::from_value(parser.load_u8(2)?);
        if status.is_none() {
            return Err(TonCellError::cell_parser_error("Missing status in ack"));
        }

        Ok(AckPacket {
            seq: packet_seq,
            status: status.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use cosmwasm_std::{CanonicalAddr, Uint128};
    use tonlib::{
        address::TonAddress,
        cell::{CellBuilder, TonCellError},
    };

    use crate::{
        transaction_parser::SEND_TO_TON_MAGIC_NUMBER,
        types::{AckPacket, BridgePacketData},
    };

    use super::{ITransactionParser, TransactionParser, RECEIVE_PACKET_MAGIC_NUMBER};

    #[test]
    fn test_load_address() {
        //case 1: None address
        let mut cell_builder = CellBuilder::new();
        cell_builder.store_u8(8, 0).unwrap();
        let res =
            TransactionParser::load_address(&mut cell_builder.build().unwrap().parser()).unwrap();
        assert_eq!(res, None);

        // case 2: Happy case
        let address: Vec<u8> = vec![
            23, 12, 3, 5, 13, 30, 10, 3, 20, 28, 27, 5, 31, 12, 11, 15, 3, 1, 22, 13, 21, 3, 30,
            20, 12, 3, 16, 0, 11, 14, 26, 4,
        ];
        let mut cell_builder = CellBuilder::new();
        cell_builder.store_u8(8, address.len() as u8).unwrap();
        cell_builder.store_slice(address.as_slice()).unwrap();
        let res =
            TransactionParser::load_address(&mut cell_builder.build().unwrap().parser()).unwrap();
        assert_eq!(res.unwrap(), CanonicalAddr::from(address))
    }

    #[test]
    fn test_parse_packet_data() {
        let seq = 1u64;
        let token_origin = 2u32;
        let amount = 3u128;
        let timeout_timestamp = 4u64;

        let mut cell_builder = CellBuilder::new();
        let tx_parser = TransactionParser::default();
        let address: Vec<u8> = vec![
            23, 12, 3, 5, 13, 30, 10, 3, 20, 28, 27, 5, 31, 12, 11, 15, 3, 1, 22, 13, 21, 3, 30,
            20, 12, 3, 16, 0, 11, 14, 26, 4,
        ];

        // case 1: invalid no-op -> invalid packet
        cell_builder
            .store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        let err = tx_parser
            .parse_packet_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TonCellError::cell_parser_error("Not a receive packet from TON to CW")
        );

        // case 2: missing receiver

        let mut cell_builder = CellBuilder::new();
        cell_builder
            .store_slice(&RECEIVE_PACKET_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        cell_builder.store_slice(&seq.to_be_bytes()).unwrap(); // seq
        cell_builder
            .store_slice(&token_origin.to_be_bytes())
            .unwrap(); // token origin
        cell_builder.store_slice(&amount.to_be_bytes()).unwrap(); // amount
        cell_builder
            .store_slice(&timeout_timestamp.to_be_bytes())
            .unwrap(); // timeout

        cell_builder.store_u8(8, 0u8).unwrap();
        let err = tx_parser
            .parse_packet_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TonCellError::cell_parser_error("receiver not contain in packet data")
        );

        // case3: missing ref
        let mut cell_builder = CellBuilder::new();
        cell_builder
            .store_slice(&RECEIVE_PACKET_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        cell_builder.store_slice(&seq.to_be_bytes()).unwrap(); // seq
        cell_builder
            .store_slice(&token_origin.to_be_bytes())
            .unwrap(); // token origin
        cell_builder.store_slice(&amount.to_be_bytes()).unwrap(); // amount
        cell_builder
            .store_slice(&timeout_timestamp.to_be_bytes())
            .unwrap(); // timeout

        cell_builder.store_u8(8, address.len() as u8).unwrap(); //store receiver bytes len
        cell_builder.store_slice(address.as_slice()).unwrap(); //store receiver
        cell_builder
            .store_address(
                &TonAddress::from_str("EQAeNPObD65owWYLyQlPdnD8qKU9SmOKOrC3q567gbjm68Or").unwrap(),
            )
            .unwrap(); // denom

        let err = tx_parser
            .parse_packet_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TonCellError::cell_parser_error(
                "Packet data does not have 1 references to parse packet data"
            )
        );

        // case 4: Happy case
        cell_builder
            .store_reference(
                &CellBuilder::new()
                    .store_address(
                        &TonAddress::from_str("EQCkkxPb0X4DAMBrOi8Tyf0wdqqVtTR9ekbDqB9ijP391nQh")
                            .unwrap(),
                    )
                    .unwrap()
                    .build()
                    .unwrap()
                    .to_arc(),
            )
            .unwrap();
        let res = tx_parser
            .parse_packet_data(&cell_builder.build().unwrap())
            .unwrap()
            .to_pretty()
            .unwrap();
        assert_eq!(
            res,
            BridgePacketData {
                seq,
                token_origin,
                timeout_timestamp,
                src_sender: "EQCkkxPb0X4DAMBrOi8Tyf0wdqqVtTR9ekbDqB9ijP391nQh".to_string(),
                src_denom: "EQAeNPObD65owWYLyQlPdnD8qKU9SmOKOrC3q567gbjm68Or".to_string(),
                amount: Uint128::from(amount),
                receiver: CanonicalAddr::from(address),
                memo: None
            }
        );
    }

    #[test]
    fn test_parse_ack_packet() {
        let seq = 1u64;
        let mut cell_builder = CellBuilder::new();
        let tx_parser = TransactionParser::default();

        // case 1: invalid no-op -> invalid packet
        cell_builder
            .store_slice(&RECEIVE_PACKET_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        let err = tx_parser
            .parse_ack_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(err, TonCellError::cell_parser_error("Not a ack"));

        // case 2: missing data => invalid packet
        let mut cell_builder = CellBuilder::new();
        cell_builder
            .store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        let err = tx_parser
            .parse_ack_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TonCellError::cell_parser_error("failed to fill whole buffer")
        );

        // case 3: wrong status => invalid packet
        cell_builder.store_slice(&seq.to_be_bytes()).unwrap();
        cell_builder.store_u8(2, 3).unwrap();
        let err = tx_parser
            .parse_ack_data(&cell_builder.build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TonCellError::cell_parser_error("Missing status in ack")
        );

        // case 4: happy case
        let mut cell_builder = CellBuilder::new();
        cell_builder
            .store_slice(&SEND_TO_TON_MAGIC_NUMBER.to_be_bytes())
            .unwrap();
        cell_builder.store_slice(&seq.to_be_bytes()).unwrap();
        cell_builder.store_u8(2, 0).unwrap();

        let res = tx_parser
            .parse_ack_data(&cell_builder.build().unwrap())
            .unwrap();
        assert_eq!(
            res,
            AckPacket {
                seq,
                status: crate::types::Status::Success
            }
        )
    }
}
