use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::{Admin, AdminResponse};
use cw_storage_plus::Item;

pub(crate) const ADMIN: Admin = Admin::new("admin");
pub(crate) const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
/// RateLimitingConfig defines parameters for rate limiting message processing
pub struct RateLimitingConfig {
    /// Maximum number of messages allowed from each FP per interval
    pub max_msgs_per_interval: u32,
    /// Number of Babylon blocks in each interval
    pub block_interval: u64,
}

#[cw_serde]
pub struct Config {
    pub bsn_id: String,
    pub min_pub_rand: u64,
    pub rate_limiting: RateLimitingConfig,
    #[schemars(range(min = 1))]
    pub bsn_activation_height: u64,
    #[schemars(range(min = 1))]
    pub finality_signature_interval: u64,
}

pub fn get_config(storage: &dyn Storage) -> StdResult<Config> {
    CONFIG.load(storage)
}

pub fn set_config(storage: &mut dyn Storage, config: &Config) -> StdResult<()> {
    CONFIG.save(storage, config)
}

pub fn get_admin(deps: Deps<BabylonQuery>) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
