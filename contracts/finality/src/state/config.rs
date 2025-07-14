use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::{Admin, AdminResponse};
use cw_storage_plus::{Item, Map};

pub(crate) const ADMIN: Admin = Admin::new("admin");
pub(crate) const CONFIG: Item<Config> = Item::new("config");

/// Map of allowed finality provider BTC public keys (in hex format) to a boolean flag
pub(crate) const ALLOWED_FINALITY_PROVIDERS: Map<String, bool> =
    Map::new("allowed_finality_providers");

/// Config are OP finality gadget's configuration
#[cw_serde]
pub struct Config {
    pub bsn_id: String,
    pub min_pub_rand: u64,
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

/// Check if a finality provider is in the allowlist
pub fn is_finality_provider_allowed(storage: &dyn Storage, fp_btc_pk_hex: &str) -> bool {
    ALLOWED_FINALITY_PROVIDERS.has(storage, fp_btc_pk_hex.to_string())
}

/// Add a finality provider to the allowlist
pub fn add_finality_provider_to_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
) -> StdResult<()> {
    ALLOWED_FINALITY_PROVIDERS.save(storage, fp_btc_pk_hex.to_string(), &true)
}

/// Remove a finality provider from the allowlist
pub fn remove_finality_provider_from_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
) -> StdResult<()> {
    ALLOWED_FINALITY_PROVIDERS.remove(storage, fp_btc_pk_hex.to_string());
    Ok(())
}

/// Get all allowed finality providers
pub fn get_allowed_finality_providers(storage: &dyn Storage) -> StdResult<Vec<String>> {
    ALLOWED_FINALITY_PROVIDERS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|item| item.map(|(key, _)| key))
        .collect()
}
