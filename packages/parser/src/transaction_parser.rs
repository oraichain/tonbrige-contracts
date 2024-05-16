use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult, Uint256};

use crate::{bit_reader::address, types::Bytes32};

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
                data.receiving_address = address(hash)?;
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
    use cosmwasm_std::{HexBinary, Uint256};

    #[test]
    fn test_address() {
        let test_number = Uint256::from(1_000_000_042u128);
        let hash = test_number.to_be_bytes();
        let ret: [u8; 20] = hash[hash.len() - 20..].try_into().unwrap();
        println!("0x{}", HexBinary::from(&ret).to_hex());
    }
}
