use cosmwasm_std::Storage;
use cw_storage_plus::Map;

use crate::error::ContractError;
use hex;

/// Map of allowed finality provider BTC public keys (as bytes) to a unit value
pub(crate) const ALLOWED_FINALITY_PROVIDERS: Map<&[u8], ()> =
    Map::new("allowed_finality_providers");

/// Check if a finality provider is in the allowlist
pub fn ensure_fp_in_allowlist(
    storage: &dyn Storage,
    fp_btc_pk_bytes: &[u8],
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .has(storage, fp_btc_pk_bytes)
        .then_some(())
        .ok_or(ContractError::FinalityProviderNotAllowed(hex::encode(
            fp_btc_pk_bytes,
        )))
}

/// Add a finality provider to the allowlist
pub fn add_finality_provider_to_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .save(storage, fp_btc_pk_bytes, &())
        .map_err(Into::into)
}

/// Remove a finality provider from the allowlist
pub fn remove_finality_provider_from_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS.remove(storage, fp_btc_pk_bytes);
    Ok(())
}

/// Get all allowed finality providers (as hex strings)
pub fn get_allowed_finality_providers(storage: &dyn Storage) -> Result<Vec<String>, ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .keys(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|item| item.map(hex::encode).map_err(Into::into))
        .collect()
}
