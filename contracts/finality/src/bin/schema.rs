use cosmwasm_schema::write_api;
use cosmwasm_std::Empty;
use finality::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: Empty,
        execute: ExecuteMsg,
    }
}
