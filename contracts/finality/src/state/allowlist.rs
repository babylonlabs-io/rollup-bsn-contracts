use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::Map;

use crate::error::ContractError;

/// Map of allowed finality provider BTC public keys (in hex format) to a boolean flag
pub(crate) const ALLOWED_FINALITY_PROVIDERS: Map<String, bool> =
    Map::new("allowed_finality_providers");

/// Check if a finality provider is in the allowlist
pub fn ensure_fp_in_allowlist(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .has(storage, fp_btc_pk_hex.to_string())
        .then_some(())
        .ok_or(ContractError::FinalityProviderNotAllowed(
            fp_btc_pk_hex.to_string(),
        ))
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
