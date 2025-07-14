use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::{Admin, AdminResponse};
use cw_storage_plus::Item;

pub(crate) const ADMIN: Admin = Admin::new("admin");
pub(crate) const CONFIG: Item<Config> = Item::new("config");

/// Config are OP finality gadget's configuration
#[cw_serde]
pub struct Config {
    pub bsn_id: String,
    pub min_pub_rand: u64,
    pub max_msgs_per_hour: u32,
}

pub fn get_config(deps: Deps<BabylonQuery>) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn set_config(storage: &mut dyn Storage, config: &Config) -> StdResult<()> {
    CONFIG.save(storage, config)
}

pub fn get_admin(deps: Deps<BabylonQuery>) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
