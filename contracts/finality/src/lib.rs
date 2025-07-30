use crate::msg::BabylonMsg;
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{entry_point, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};
use error::ContractError;
use msg::{ExecuteMsg, InstantiateMsg};

pub mod contract;
pub mod custom_queries;
pub mod error;
pub mod exec;
pub mod msg;
pub mod queries;
pub mod state;
pub mod utils;
pub mod validation;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::instantiate(deps, env, info, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps<BabylonQuery>,
    env: Env,
    msg: msg::QueryMsg,
) -> Result<QueryResponse, ContractError> {
    contract::query(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::execute(deps, env, info, msg)
}

#[cfg(test)]
pub mod testutil;
