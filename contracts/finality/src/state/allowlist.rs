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
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    let key = hex::decode(fp_btc_pk_hex)?;
    ALLOWED_FINALITY_PROVIDERS
        .has(storage, &key)
        .then_some(())
        .ok_or(ContractError::FinalityProviderNotAllowed(
            fp_btc_pk_hex.to_string(),
        ))
}

/// Add a finality provider to the allowlist
pub fn add_finality_provider_to_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    let key = hex::decode(fp_btc_pk_hex)?;
    ALLOWED_FINALITY_PROVIDERS
        .save(storage, &key, &())
        .map_err(Into::into)
}

/// Remove a finality provider from the allowlist
pub fn remove_finality_provider_from_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    let key = hex::decode(fp_btc_pk_hex)?;
    ALLOWED_FINALITY_PROVIDERS.remove(storage, &key);
    Ok(())
}

/// Get all allowed finality providers (as hex strings)
pub fn get_allowed_finality_providers(storage: &dyn Storage) -> Result<Vec<String>, ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .keys(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|item| item.map(hex::encode).map_err(Into::into))
        .collect()
}
