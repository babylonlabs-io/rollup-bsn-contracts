use cosmwasm_schema::write_api;
use finality::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: MigrateMsg,
        execute: ExecuteMsg,
    }
}
