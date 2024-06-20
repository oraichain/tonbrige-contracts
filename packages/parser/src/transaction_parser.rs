use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult, Uint128, Uint256};
use tonlib::cell::Cell;

use crate::types::{BridgePacketData, Bytes32};

use super::{
    bit_reader::{
        parse_dict, read_bit, read_bool, read_bytes32_bit_size, read_bytes32_byte_size, read_cell,
        read_u32, read_u64, read_u8, read_uint256,
    },
    block_parser::{parse_currency_collection, read_coins},
    types::{
        CellData, Message, MessagesHeader, PacketData, RawCommonMessageInfo, TonAddress,
        TransactionHeader,
    },
};

pub trait ITransactionParser {
    fn deserialize_msg_date(
        &self,
        boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<PacketData>;

    fn parse_transaction_header(
        &self,
        data: &[u8],
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<TransactionHeader>;

    fn parse_messages_header(
        &self,
        data: &[u8],
        cells: &mut [CellData],
        messages_idx: usize,
    ) -> StdResult<MessagesHeader>;

    fn get_data_from_messages(
        &self,
        boc_data: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        out_messages: &mut [Message; 5],
    ) -> StdResult<PacketData>;

    fn parse_packet_data(&self, cell: &Cell) -> StdResult<BridgePacketData>;
}

#[cw_serde]
#[derive(Default)]
pub struct TransactionParser {}

impl ITransactionParser for TransactionParser {
    fn deserialize_msg_date(
        &self,
        boc: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<PacketData> {
        self.parse_transaction_header(boc, cells, root_idx)?;
        let message_idx = read_cell(cells, root_idx);
        let mut messages = self.parse_messages_header(boc, cells, message_idx)?;

        self.get_data_from_messages(boc, opcode, cells, &mut messages.out_messages)
    }

    fn parse_transaction_header(
        &self,
        data: &[u8],
        cells: &mut [CellData],
        root_idx: usize,
    ) -> StdResult<TransactionHeader> {
        let mut transaction = TransactionHeader::default();
        transaction.check_code = read_u8(data, cells, root_idx, 4)?;
        // addressHash
        transaction.address_hash = read_bytes32_byte_size(data, cells, root_idx, 32);
        // lt
        transaction.lt = read_u64(data, cells, root_idx, 64)?;
        transaction.prev_trans_hash = read_bytes32_byte_size(data, cells, root_idx, 32);
        transaction.prev_trans_lt = read_u64(data, cells, root_idx, 64)?;
        transaction.time = read_u32(data, cells, root_idx, 32)?;
        transaction.out_mesages_count = read_u32(data, cells, root_idx, 15)?;

        transaction.old_status = read_u8(data, cells, root_idx, 2)?;
        transaction.new_status = read_u8(data, cells, root_idx, 2)?;

        transaction.fees = parse_currency_collection(data, cells, root_idx)?;

        Ok(transaction)
    }

    fn parse_messages_header(
        &self,
        data: &[u8],
        cells: &mut [CellData],
        messages_idx: usize,
    ) -> StdResult<MessagesHeader> {
        let mut message_header = MessagesHeader::default();

        message_header.has_in_message = read_bool(data, cells, messages_idx);
        message_header.has_out_messages = read_bool(data, cells, messages_idx);
        if message_header.has_in_message {
            let message_idx = read_cell(cells, messages_idx);
            message_header.in_message = parse_message(data, cells, message_idx)?;
        }

        if message_header.has_out_messages {
            let message_idx = read_cell(cells, messages_idx);
            let cell_idxs = parse_dict(data, cells, message_idx, 15)?;
            let mut j = 0;
            for cell_idx in cell_idxs {
                if cell_idx != 255 {
                    let message_idx = read_cell(cells, cell_idx);
                    message_header.out_messages[j] = parse_message(data, cells, message_idx)?;
                    j += 1;
                }
            }
        }

        Ok(message_header)
    }

    fn get_data_from_messages(
        &self,
        boc_data: &[u8],
        opcode: Bytes32,
        cells: &mut [CellData],
        out_messages: &mut [Message; 5],
    ) -> StdResult<PacketData> {
        let mut data = PacketData {
            receiving_address: Default::default(),
            amount: Uint256::default(),
        };
        // FIXME: exhaust all packet data from the messages
        for out_message in out_messages {
            // console.log(out_messages[i].body_idx, cells[out_messages[i].body_idx].cursor);
            // 0xF0A28992
            // 0xc0470ccf
            // console.logBytes(boc_data[cells[out_messages[i].body_idx].cursor / 8:]);
            if out_message.info.dest.hash == opcode {
                let idx = out_message.body_idx;
                let hash = read_bytes32_bit_size(boc_data, cells, idx, 256);
                // data.receiving_address = address(hash)?;
                // data.amount = 0;
                // console.log("amount");
                // console.log(uint(read_coins(boc_data, cells, idx)));
                // data.amount = read_u64(boc_data, cells, idx, 16);
                data.amount = read_uint256(boc_data, cells, idx, 256)?;
                // FIXME: add receiving token parser as well
            }
        }

        Ok(data)
    }

    fn parse_packet_data(&self, cell: &Cell) -> StdResult<BridgePacketData> {
        let mut parser = cell.parser();

        let source_denom = parser.load_address().unwrap();
        let amount = parser.load_coins().unwrap();

        let mut des_denom: Vec<u8> = vec![];

        cell.references[0].references[0]
            .load_buffer(&mut des_denom)
            .unwrap();
        let mut des_channel: Vec<u8> = vec![];
        cell.references[0].references[1]
            .load_buffer(&mut des_channel)
            .unwrap();
        let mut des_receiver: Vec<u8> = vec![];
        cell.references[0].references[2]
            .load_buffer(&mut des_receiver)
            .unwrap();
        let mut orai_address: Vec<u8> = vec![];
        cell.references[0].references[3]
            .load_buffer(&mut orai_address)
            .unwrap();

        Ok(BridgePacketData {
            denom: source_denom.to_string(),
            amount: Uint128::from_str(&amount.to_str_radix(10))?,
            dest_denom: String::from_utf8(des_denom)?,
            dest_channel: String::from_utf8(des_channel)?,
            dest_receiver: String::from_utf8(des_receiver)?,
            orai_address: String::from_utf8(orai_address)?,
        })
    }
}

pub fn parse_state_init(data: &[u8], cells: &mut [CellData], idx: usize) {
    if read_bool(data, cells, idx) {
        read_bytes32_bit_size(data, cells, idx, 5);
    }
    if read_bool(data, cells, idx) {
        read_bytes32_bit_size(data, cells, idx, 2);
    }
}

fn parse_message(data: &[u8], cells: &mut [CellData], message_idx: usize) -> StdResult<Message> {
    let info = parse_common_msg_info(data, cells, message_idx)?;
    let has_init = read_bool(data, cells, message_idx);

    if has_init {
        if read_bool(data, cells, message_idx) {
            // init = parse_state_init(slice);
            // console.log("has init curr");
            // parse_state_init(data, cells, message_idx);
        } else {
            // console.log("has init ref");
            // init = parse_state_init(slice.readRef());
            read_cell(cells, message_idx);
        }
    }

    let flag = read_bool(data, cells, message_idx);
    // console.log("body is ref?");
    // console.log(flag);
    // console.logBytes(flag ? data[cells[cells[message_idx].cursorRef].cursor / 8:] : data[cells[message_idx].cursor / 8:]);

    let body_idx = if flag {
        read_cell(cells, message_idx)
    } else {
        message_idx
    };

    Ok(Message { info, body_idx })
}

fn parse_common_msg_info(
    data: &[u8],
    cells: &mut [CellData],
    message_idx: usize,
) -> StdResult<RawCommonMessageInfo> {
    let mut msg_info = RawCommonMessageInfo::default();

    if !read_bool(data, cells, message_idx) {
        // internal

        msg_info.ihr_disabled = read_bool(data, cells, message_idx);
        msg_info.bounce = read_bool(data, cells, message_idx);
        msg_info.bounced = read_bool(data, cells, message_idx);

        msg_info.src = read_address(data, cells, message_idx)?;
        msg_info.dest = read_address(data, cells, message_idx)?;

        msg_info.value = parse_currency_collection(data, cells, message_idx)?;
        msg_info.ihr_fee = read_coins(data, cells, message_idx)?;
        msg_info.fwd_fee = read_coins(data, cells, message_idx)?;
        msg_info.created_lt = Uint256::from(read_u64(data, cells, message_idx, 64)?);
        msg_info.created_at = Uint256::from(read_u32(data, cells, message_idx, 32)?);
    } else if read_bool(data, cells, message_idx) {
        // Outgoing external
        msg_info.src = read_address(data, cells, message_idx)?;
        msg_info.dest = read_address(data, cells, message_idx)?;

        msg_info.created_lt = Uint256::from(read_u64(data, cells, message_idx, 64)?);
        msg_info.created_at = Uint256::from(read_u32(data, cells, message_idx, 32)?);
    } else {
        // Incoming external
        msg_info.src = read_address(data, cells, message_idx)?;
        msg_info.dest = read_address(data, cells, message_idx)?;
        msg_info.import_fee = read_coins(data, cells, message_idx)?;
    }

    Ok(msg_info)
}

fn read_address(data: &[u8], cells: &mut [CellData], message_idx: usize) -> StdResult<TonAddress> {
    let mut addr = TonAddress::default();

    let cell_type = read_u8(data, cells, message_idx, 2)?;

    if cell_type == 0 {
        return Ok(addr);
    }
    if cell_type == 1 {
        let len = read_u64(data, cells, message_idx, 9)?;
        addr.hash = read_bytes32_bit_size(data, cells, message_idx, len as usize);
        return Ok(addr);
    }

    if cell_type != 2 {
        return Err(StdError::generic_err(
            "Only STD address supported TYPE ERROR",
        ));
    }

    let bit = read_bit(data, cells, message_idx);

    if bit != 0 {
        return Err(StdError::generic_err(
            "Only STD address supported BIT ERROR",
        ));
    }

    addr.wc = read_u8(data, cells, message_idx, 8)?;

    addr.hash = read_bytes32_byte_size(data, cells, message_idx, 32);

    Ok(addr)
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
                packet_data,
                BridgePacketData {
                    denom: "EQB76ac6w5o4fyBzzpGcJeMPOfltDqpBbKWSoXU0w0ygCYVs".to_string(),
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
