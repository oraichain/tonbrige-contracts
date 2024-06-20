use cosmwasm_std::{Api, CosmosMsg, QuerierWrapper, StdError, StdResult, Uint128};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw20_ics20_msg::amount::convert_remote_to_local;
use oraiswap::asset::{Asset, AssetInfo};
use tonbridge_bridge::state::MappingMetadata;
use tonbridge_parser::{
    transaction_parser::TransactionParser,
    tree_of_cells_parser::{OPCODE_1, OPCODE_2},
    types::{BridgePacketData, Bytes32},
};

pub trait IBaseAdapter {
    fn execute(
        &self,
        api: &dyn Api,
        querier: &QuerierWrapper,
        data: BridgePacketData,
        opcode: Bytes32,
        bridge_token_mapping: MappingMetadata,
    ) -> StdResult<Vec<CosmosMsg>>;
}

pub struct Adapter {
    pub transaction_parser: TransactionParser,
}

impl Adapter {
    pub fn new() -> Self {
        Self {
            transaction_parser: Default::default(),
        }
    }
}

impl IBaseAdapter for Adapter {
    fn execute(
        &self,
        api: &dyn Api,
        querier: &QuerierWrapper,
        data: BridgePacketData,
        opcode: Bytes32,
        mapping: MappingMetadata,
    ) -> StdResult<Vec<CosmosMsg>> {
        let mut cosmos_msgs: Vec<CosmosMsg> = vec![];
        let recipient = api.addr_validate(&data.orai_address)?;

        let remote_amount: Uint128 = data.amount;
        let local_amount = convert_remote_to_local(
            remote_amount,
            mapping.remote_decimals,
            mapping.asset_info_decimals,
        )?;
        let msg = Asset {
            info: mapping.asset_info.clone(),
            amount: local_amount,
        };
        if opcode == OPCODE_1 {
            let msg = match msg.info {
                AssetInfo::NativeToken { denom: _ } => {
                    return Err(StdError::generic_err("Cannot mint a native token"))
                }
                AssetInfo::Token { contract_addr } => {
                    Cw20Contract(contract_addr).call(Cw20ExecuteMsg::Mint {
                        recipient: recipient.to_string(),
                        amount: local_amount,
                    })
                }
            }?;
            cosmos_msgs.push(msg);
        } else if opcode == OPCODE_2 {
            cosmos_msgs.push(msg.into_msg(None, querier, recipient)?);
        }

        Ok(cosmos_msgs)
    }
}
