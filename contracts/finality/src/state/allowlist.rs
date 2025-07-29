use cosmwasm_std::Storage;
use cw_storage_plus::{SnapshotMap, Strategy};
use std::collections::HashSet;

use crate::error::ContractError;
use hex;

/// SnapshotMap of allowed finality provider BTC public keys stored as a HashSet
pub(crate) const ALLOWED_FINALITY_PROVIDERS: SnapshotMap<&str, HashSet<Vec<u8>>> =
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
    let fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load(storage, "allowlist")?
        .unwrap_or_default();
    
    if fp_set.contains(fp_btc_pk_bytes) {
        Ok(())
    } else {
        Err(ContractError::FinalityProviderNotAllowed(hex::encode(
            fp_btc_pk_bytes,
        )))
    }
}

/// Check if a finality provider was in the allowlist at a specific Babylon height
pub fn ensure_fp_in_allowlist_at_height(
    storage: &dyn Storage,
    fp_btc_pk_bytes: &[u8],
    babylon_height: u64,
) -> Result<(), ContractError> {
    let fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load_at_height(storage, "allowlist", babylon_height)
        .map_err(ContractError::StdError)?
        .unwrap_or_default();
    
    if fp_set.contains(fp_btc_pk_bytes) {
        Ok(())
    } else {
        Err(ContractError::FinalityProviderNotAllowed(hex::encode(
            fp_btc_pk_bytes,
        )))
    }
}

/// Add a finality provider to the allowlist at a specific Babylon height
pub fn add_finality_provider_to_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
    babylon_height: u64,
) -> Result<(), ContractError> {
    // Load current allowlist
    let mut fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load(storage, "allowlist")?
        .unwrap_or_default();
    
    // Add the new FP (HashSet automatically handles duplicates)
    fp_set.insert(fp_btc_pk_bytes.to_vec());
    
    // Save updated allowlist with height
    ALLOWED_FINALITY_PROVIDERS
        .save(storage, "allowlist", &fp_set, babylon_height)
        .map_err(Into::into)
}

/// Remove a finality provider from the allowlist at a specific Babylon height
pub fn remove_finality_provider_from_allowlist(
    storage: &mut dyn Storage,
    fp_btc_pk_bytes: &[u8],
    babylon_height: u64,
) -> Result<(), ContractError> {
    // Load current allowlist
    let mut fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load(storage, "allowlist")?
        .unwrap_or_default();
    
    // Remove the FP
    fp_set.remove(fp_btc_pk_bytes);
    
    // Save updated allowlist with height
    ALLOWED_FINALITY_PROVIDERS
        .save(storage, "allowlist", &fp_set, babylon_height)
        .map_err(Into::into)
}

/// Get all allowed finality providers (as hex strings) at current height
pub fn get_allowed_finality_providers(storage: &dyn Storage) -> Result<Vec<String>, ContractError> {
    let fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load(storage, "allowlist")?
        .unwrap_or_default();
    
    let hex_strings: Vec<String> = fp_set.iter()
        .map(|bytes| hex::encode(bytes))
        .collect();
    
    Ok(hex_strings)
}

/// Get all allowed finality providers (as hex strings) at a specific Babylon height
pub fn get_allowed_finality_providers_at_height(
    storage: &dyn Storage, 
    babylon_height: u64
) -> Result<Vec<String>, ContractError> {
    let fp_set = ALLOWED_FINALITY_PROVIDERS
        .may_load_at_height(storage, "allowlist", babylon_height)
        .map_err(ContractError::StdError)?
        .unwrap_or_default();
    
    let hex_strings: Vec<String> = fp_set.iter()
        .map(|bytes| hex::encode(bytes))
        .collect();
    
    Ok(hex_strings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;

    #[test]
    fn test_hashset_allowlist_functionality() {
        let mut deps = mock_dependencies();
        let storage = deps.as_mut().storage;
        
        let fp1 = b"provider1";
        let fp2 = b"provider2";
        let fp3 = b"provider3";
        let fp4 = b"provider4";
        
        // Height 100: Add fp1, fp2, fp3
        add_finality_provider_to_allowlist(storage, fp1, 100).unwrap();
        add_finality_provider_to_allowlist(storage, fp2, 100).unwrap();
        add_finality_provider_to_allowlist(storage, fp3, 100).unwrap();
        
        // Height 105: Remove fp3, Add fp4
        remove_finality_provider_from_allowlist(storage, fp3, 105).unwrap();
        add_finality_provider_to_allowlist(storage, fp4, 105).unwrap();
        
        // Test individual checks at current height
        assert!(ensure_fp_in_allowlist(storage, fp1).is_ok());
        assert!(ensure_fp_in_allowlist(storage, fp2).is_ok());
        assert!(ensure_fp_in_allowlist(storage, fp3).is_err(), "fp3 should be removed");
        assert!(ensure_fp_in_allowlist(storage, fp4).is_ok());
        
        // Test individual checks at historical heights
        
        // At height 102 (should use state from height 100)
        assert!(ensure_fp_in_allowlist_at_height(storage, fp1, 102).is_ok());
        assert!(ensure_fp_in_allowlist_at_height(storage, fp3, 102).is_ok(), "fp3 existed at height 102");
        assert!(ensure_fp_in_allowlist_at_height(storage, fp4, 102).is_err(), "fp4 didn't exist at height 102");
        
        // At height 107 (should use state from height 105)
        assert!(ensure_fp_in_allowlist_at_height(storage, fp1, 107).is_ok());
        assert!(ensure_fp_in_allowlist_at_height(storage, fp4, 107).is_ok());
        assert!(ensure_fp_in_allowlist_at_height(storage, fp3, 107).is_err(), "fp3 was removed by height 107");
        
        // Test complete list reconstruction
        
        // At height 102 (should get state from height 100): [fp1, fp2, fp3]
        let list_at_102 = get_allowed_finality_providers_at_height(storage, 102).unwrap();
        assert_eq!(list_at_102.len(), 3);
        assert!(list_at_102.contains(&hex::encode(fp1)));
        assert!(list_at_102.contains(&hex::encode(fp2)));
        assert!(list_at_102.contains(&hex::encode(fp3)));
        assert!(!list_at_102.contains(&hex::encode(fp4)));
        
        // At height 107 (should get state from height 105): [fp1, fp2, fp4]
        let list_at_107 = get_allowed_finality_providers_at_height(storage, 107).unwrap();
        assert_eq!(list_at_107.len(), 3);
        assert!(list_at_107.contains(&hex::encode(fp1)));
        assert!(list_at_107.contains(&hex::encode(fp2)));
        assert!(list_at_107.contains(&hex::encode(fp4)));
        assert!(!list_at_107.contains(&hex::encode(fp3)));
        
        // Test current list
        let current_list = get_allowed_finality_providers(storage).unwrap();
        assert_eq!(current_list.len(), 3);
        assert!(current_list.contains(&hex::encode(fp1)));
        assert!(current_list.contains(&hex::encode(fp2)));
        assert!(current_list.contains(&hex::encode(fp4)));
        

    }
}
