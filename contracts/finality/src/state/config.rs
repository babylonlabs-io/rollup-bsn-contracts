use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult};
use cw_controllers::{Admin, AdminResponse};
use cw_storage_plus::Item;

pub const ADMIN: Admin = Admin::new("admin");
pub const CONFIG: Item<Config> = Item::new("config");

/// Config are OP finality gadget's configuration
#[cw_serde]
pub struct Config {
    pub bsn_id: String,
    // If the finality gadget is disabled, it will always return true for the is finalized query
    pub is_enabled: bool,
}

pub fn get_config(deps: Deps<BabylonQuery>) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn get_admin(deps: Deps<BabylonQuery>) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
