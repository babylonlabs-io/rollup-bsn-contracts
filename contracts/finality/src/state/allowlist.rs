use cosmwasm_std::Storage;
use cw_storage_plus::{SnapshotMap, Strategy};

use crate::error::ContractError;
use hex;

/// SnapshotMap of allowed finality provider BTC public keys (as bytes) to a unit value
/// This allows querying the allowlist at specific heights
pub(crate) const ALLOWED_FINALITY_PROVIDERS: SnapshotMap<&[u8], ()> =
    SnapshotMap::new(
        "allowed_finality_providers",
        "allowed_finality_providers__checkpoints", 
        "allowed_finality_providers__changelog",
        Strategy::EveryBlock
    );

/// Check if a finality provider is in the allowlist (at current height)
pub fn ensure_fp_in_allowlist(
    storage: &dyn Storage,
    fp_btc_pk_bytes: &[u8],
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .may_load(storage, fp_btc_pk_bytes)
        .map_err(ContractError::StdError)?
        .is_some()
        .then_some(())
        .ok_or(ContractError::FinalityProviderNotAllowed(hex::encode(
            fp_btc_pk_bytes,
        )))
}

/// Check if a finality provider was in the allowlist at a specific height
pub fn ensure_fp_in_allowlist_at_height(
    storage: &dyn Storage,
    fp_btc_pk_bytes: &[u8],
    height: u64,
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .may_load_at_height(storage, fp_btc_pk_bytes, height)
        .map_err(ContractError::StdError)?
        .is_some()
        .then_some(())
        .ok_or(ContractError::FinalityProviderNotAllowed(hex::encode(
            fp_btc_pk_bytes,
        )))
}

/// Add a finality provider to the allowlist at the current height
pub fn add_finality_provider_to_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
    height: u64,
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .save(storage, fp_btc_pk_bytes, &(), height)
        .map_err(Into::into)
}

/// Remove a finality provider from the allowlist at the current height
pub fn remove_finality_provider_from_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
    height: u64,
) -> Result<(), ContractError> {
    ALLOWED_FINALITY_PROVIDERS.remove(storage, fp_btc_pk_bytes, height)?;
    Ok(())
}

/// Get all allowed finality providers (as hex strings) at current height
pub fn get_allowed_finality_providers(storage: &dyn Storage) -> Result<Vec<String>, ContractError> {
    ALLOWED_FINALITY_PROVIDERS
        .keys(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|item| item.map(hex::encode).map_err(Into::into))
        .collect()
}

/// Get all allowed finality providers (as hex strings) at a specific height
/// Note: This function iterates through all keys and checks if they existed at the given height
pub fn get_allowed_finality_providers_at_height(
    storage: &dyn Storage, 
    height: u64
) -> Result<Vec<String>, ContractError> {
    // Since SnapshotMap doesn't have a direct keys_at_height method,
    // we need to iterate through all current keys and check if they existed at the given height
    let current_keys: Result<Vec<_>, _> = ALLOWED_FINALITY_PROVIDERS
        .keys(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect();
    
    let mut keys_at_height = Vec::new();
    for key in current_keys? {
        // Check if this key existed at the specified height
        if ALLOWED_FINALITY_PROVIDERS
            .may_load_at_height(storage, &key, height)
            .map_err(ContractError::StdError)?
            .is_some()
        {
            keys_at_height.push(hex::encode(key));
        }
    }
    
    Ok(keys_at_height)
}
