use crate::msg::{ExecuteMsg, QueryMsg};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    to_binary, Addr, Binary, CosmosMsg, CustomQuery, QuerierWrapper, QueryRequest, StdResult,
    WasmMsg, WasmQuery,
};

/// ValidatorWrapper is a wrapper around Addr that provides a lot of helpers for the Validator contract
/// for working with this.
#[cw_serde]
pub struct ValidatorWrapper(pub Addr);

impl ValidatorWrapper {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<ExecuteMsg>>(&self, msg: T) -> StdResult<CosmosMsg> {
        let msg = to_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }

    fn encode_smart_query<CQ: CustomQuery>(&self, msg: QueryMsg) -> StdResult<QueryRequest<CQ>> {
        Ok(WasmQuery::Smart {
            contract_addr: self.addr().into(),
            msg: to_binary(&msg)?,
        }
        .into())
    }

    /// Check if a block is verified
    pub fn is_verified_block<CQ>(
        &self,
        querier: &QuerierWrapper<CQ>,
        root_hash: Binary,
    ) -> StdResult<bool>
    where
        CQ: CustomQuery,
    {
        let query = self.encode_smart_query(QueryMsg::IsVerifiedBlock { root_hash })?;
        querier.query(&query)
    }
}
