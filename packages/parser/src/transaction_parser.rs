use cosmwasm_schema::cw_serde;
use tonlib::cell::{Cell, TonCellError};

use crate::types::BridgePacketDataRaw;

pub trait ITransactionParser {
    fn parse_packet_data(&self, cell: &Cell) -> Result<BridgePacketDataRaw, TonCellError>;
    fn parse_send_packet_timeout_data(&self, cell: &Cell) -> Result<u64, TonCellError>;
    fn parse_ack_data(&self, cell: &Cell) -> Result<u64, TonCellError>;
}

pub const SEND_PACKET_TIMEOUT_MAGIC_NUMBER: u32 = 0x540da70d; // crc32("ops::timeout_send_packet")
pub const RECEIVE_PACKET_MAGIC_NUMBER: u32 = 0xa64c12a3; // crc32("op::send_to_cosmos")
pub const ACK_MAGIC_NUMBER: u32 = 0x3acb0e2; // crc32("ops::ack_success")

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

    fn parse_ack_data(&self, cell: &Cell) -> Result<u64, TonCellError> {
        let mut parser = cell.parser();
        let magic_number = parser.load_u32(32)?;
        if magic_number != ACK_MAGIC_NUMBER {
            return Err(TonCellError::cell_parser_error("Not a ack"));
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
        let tx_boc = HexBinary::from_hex("b5ee9c720102140100036c0003b5772dfc6058ff935f1509e1581250a9a69fe5cd2f1f736eaa67f5ef1302940506d00002b38f30edb0110b3ab4393cbe2fb1708b43f55c6d24e909325544c94bb7de64cfd0fa2bdb7a900002b38f2a40b4366866a4a0005469dc4a680102030201e004050082729cc85b33466874bc28b8678bb2f9769358986535f948d63306bb4297e61ba1ecb785117fa81768757a416242202a4f2d412533ae25f9c4be7ef416ecfa1c152e02170444090e08871c186794d211121301b1680026199d4cf9ecc6786607ea6ab5d07ebb2b7300531ce1d62713126b93e9b547fb001cb7f18163fe4d7c542785604942a69a7f9734bc7dcdbaa99fd7bc4c0a50141b50e08871c0061739e200005671e5a3a404cd0cd47ec0060201dd090a0118af35dc85000000000000000007025dffff800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01be6030d4000000000cd0cefb10e0800438002dca7653b4c646d7d66400ffc787b1f6d70e8a404e3438ee55e6376927dfb19d00101200b0101200c00c94800e5bf8c0b1ff26be2a13c2b024a1534d3fcb9a5e3ee6dd54cfebde2605280a0db0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63390df7d6d800608235a00005671e61db604cd0cd4946a993b6d800000000000000040019fe00396fe302c7fc9af8a84f0ac092854d34ff2e6978fb9b75533faf789814a02836b009280cf31dd9d4f328084b3b6dc433d204ee97852960f7c44ce2c4170ce15a07c00002b38f30edb0366866a4a600d01b9a64c12a3000000000000000100000000668677d8800fc61f856eea374b146c85e7fab3abd2d5021bbaf1b146217fd06a77de20a01bf0005b94eca7698c8dafacc801ff8f0f63edae1d14809c6871dcabcc6ed24fbf63380000c061a8200e0400100f101100126368616e6e656c2d30000000566f72616931717478346d6b77356b363635736e74376a6a397567356439303233686b7a6175656873303477009e44da2c3d09000000000000000000c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006fc98b26b04c48eecc000000000004000000000004db981dbe2b040c835c86fb376b39824f59ff18cc098a56d73637003e7730a2f041d050ec").unwrap();

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
                    seq: 1,
                    timeout_timestamp: 1720088536,
                    src_sender: "EQAW5Tsp2mMja-syAH_jw9j7a4dFICcaHHcq8xu0k-_Yzs_T".to_string(),
                    src_denom: "EQB-MPwrd1G6WKNkLz_VnV6WqBDd142KMQv-g1O-8QUA3728".to_string(),
                    src_channel: "channel-0".to_string(),
                    amount: Uint128::from_str("100000").unwrap(),
                    dest_denom: "".to_string(),
                    dest_channel: "channel-0".to_string(),
                    dest_receiver: "".to_string(),
                    orai_address: "orai1qtx4mkw5k665snt7jj9ug5d9023hkzauehs04w".to_string()
                }
            )
        }
    }
}
