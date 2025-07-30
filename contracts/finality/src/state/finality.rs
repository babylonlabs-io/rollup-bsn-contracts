use crate::{
    error::ContractError,
    state::pruning::{DEFAULT_PRUNING, MAX_PRUNING},
};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Map};
use std::collections::HashSet;

/// Map of (block height, finality provider public key) tuples to the finality signatures for that height.
const FINALITY_SIGNATURES: Map<(u64, &[u8]), HashSet<FinalitySigInfo>> =
    Map::new("finality_signatures");

/// Maps finality provider BTC public key to their highest voted height.
/// This enables O(1) lookup of the maximum rollup block height an FP has voted on.
const HIGHEST_VOTED_HEIGHT: Map<&[u8], u64> = Map::new("highest_voted_height");

pub fn list_finality_signatures(
    storage: &dyn Storage,
    height: u64,
    fp_btc_pk: &[u8],
) -> Result<Option<HashSet<FinalitySigInfo>>, ContractError> {
    FINALITY_SIGNATURES
        .may_load(storage, (height, fp_btc_pk))
        .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), height))
}

/// Inserts a finality signature into the FINALITY_SIGNATURES map.
/// Adds the new signature to the set for the given height and finality provider.
/// Returns an error if the signature already exists.
pub fn insert_finality_signature(
    storage: &mut dyn Storage,
    height: u64,
    fp_btc_pk: &[u8],
    finality_sig_info: FinalitySigInfo,
) -> Result<(), ContractError> {
    let mut signatures = FINALITY_SIGNATURES
        .may_load(storage, (height, fp_btc_pk))
        .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), height))?
        .unwrap_or_default();

    if !signatures.insert(finality_sig_info) {
        return Err(ContractError::DuplicatedFinalitySig(
            hex::encode(fp_btc_pk),
            height,
        ));
    }

    Ok(FINALITY_SIGNATURES.save(storage, (height, fp_btc_pk), &signatures)?)
}

/// Map of (block height, block hash) tuples to the list of signatories
/// (each identified by the BTC public key in hex) for that block.
const SIGNATORIES_BY_BLOCK_HASH: Map<(u64, &[u8]), HashSet<String>> =
    Map::new("signatories_by_block_hash");

pub fn get_signatories_by_block_hash(
    storage: &dyn Storage,
    height: u64,
    block_hash: &[u8],
) -> Result<Option<HashSet<String>>, ContractError> {
    SIGNATORIES_BY_BLOCK_HASH
        .may_load(storage, (height, block_hash))
        .map_err(|_| ContractError::FailedToLoadSignatories(hex::encode(block_hash), height))
}

/// Inserts a set of signatories into the SIGNATORIES_BY_BLOCK_HASH map.
/// This will override any existing set for the same height and block hash.
pub fn insert_signatories_by_block_hash(
    storage: &mut dyn Storage,
    height: u64,
    block_hash: &[u8],
    signatories: HashSet<String>,
) -> StdResult<()> {
    SIGNATORIES_BY_BLOCK_HASH.save(storage, (height, block_hash), &signatories)
}

/// FinalitySigInfo is a struct that contains the finality signature and
/// block hash for a given block height and fp
#[cw_serde]
#[derive(Hash, Eq)]
pub struct FinalitySigInfo {
    /// the finality signature
    pub finality_sig: Vec<u8>,
    /// the block hash that the finality signature is for
    pub block_hash: Vec<u8>,
}

/// Inserts a signatory into the SIGNATORIES_BY_BLOCK_HASH map for the given height and block hash.
/// The function does not do any checks:
/// - If the signatory is already there, return an error.
/// - If the signatory is a new one, the caller is responsible for ensuring that they are
///   inserting the right one. An insertion without a corresponding entry for a finality provider
fn insert_signatory(
    storage: &mut dyn Storage,
    height: u64,
    block_hash: &[u8],
    signatory: &str,
) -> Result<(), ContractError> {
    let mut set = SIGNATORIES_BY_BLOCK_HASH
        .may_load(storage, (height, block_hash))?
        .unwrap_or_else(HashSet::new);
    if !set.insert(signatory.to_string()) {
        return Err(ContractError::DuplicateSignatory(signatory.to_string()));
    }
    insert_signatories_by_block_hash(storage, height, block_hash, set)?;
    Ok(())
}

/// Inserts finality sig and signatory into storage.
/// Returns an error if any of the operations fail.
pub fn insert_finality_sig_and_signatory(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
    block_hash: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // Save the finality signature
    let finality_sig_info = FinalitySigInfo {
        finality_sig: signature.to_vec(),
        block_hash: block_hash.to_vec(),
    };
    insert_finality_signature(storage, height, fp_btc_pk, finality_sig_info)?;

    // Add the fp_btc_pk to the signatories for the (height, block_hash) pair
    insert_signatory(storage, height, block_hash, &hex::encode(fp_btc_pk))?;

    // Update the highest voted height for this finality provider
    update_highest_voted_height(storage, fp_btc_pk, height)?;

    Ok(())
}

/// Gets the highest voted height for a specific finality provider.
/// Returns None if the finality provider has never voted.
pub fn get_highest_voted_height(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
) -> Result<Option<u64>, ContractError> {
    HIGHEST_VOTED_HEIGHT
        .may_load(storage, fp_btc_pk)
        .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), 0))
}

/// Updates the highest voted height for a finality provider if the new height is higher.
/// This is called internally when a finality signature is inserted.
fn update_highest_voted_height(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<(), ContractError> {
    let current_highest = HIGHEST_VOTED_HEIGHT
        .may_load(storage, fp_btc_pk)
        .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), height))?
        .unwrap_or(0);

    if height > current_highest {
        HIGHEST_VOTED_HEIGHT
            .save(storage, fp_btc_pk, &height)
            .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), height))?;
    }

    Ok(())
}

/// Prunes old finality signatures for all finality providers.
///
/// This function removes all finality signatures for rollup blocks with height <= rollup_height.
/// It's designed to be called manually by the admin to prevent indefinite storage growth.
///
/// The function prunes up to `max_signatures_to_prune` old signatures per call
/// to prevent gas exhaustion when there are many old signatures to clean up.
///
/// # Arguments
///
/// * `storage` - The storage instance to operate on
/// * `rollup_height` - Remove all signatures for rollup blocks with height <= this value
/// * `max_signatures_to_prune` - Maximum number of signatures to prune in this operation
///     - If not provided, the default value is 10.
///     - If provided, the value must be between 1 and 30.
///
/// # Returns
///
/// Returns the number of signatures that were pruned, or an error if the operation failed.
pub(crate) fn prune_finality_signatures(
    storage: &mut dyn Storage,
    rollup_height: u64,
    max_signatures_to_prune: Option<u32>,
) -> Result<usize, ContractError> {
    let max_to_prune = max_signatures_to_prune
        .unwrap_or(DEFAULT_PRUNING)
        .min(MAX_PRUNING) as usize;

    // Get max finality signatures to prune in range from storage, ordered by height (ascending)
    let all_signatures = FINALITY_SIGNATURES
        .range(
            storage,
            None,
            Some(Bound::exclusive((rollup_height + 1, &[] as &[u8]))),
            cosmwasm_std::Order::Ascending,
        )
        .take(max_to_prune)
        .collect::<cosmwasm_std::StdResult<Vec<_>>>()?;

    for (key, _finality_sig_info) in &all_signatures {
        let (height, fp_btc_pk) = key;
        // Remove the signature from storage
        FINALITY_SIGNATURES.remove(storage, (*height, fp_btc_pk.as_slice()));
    }

    // Note: We intentionally do NOT modify HIGHEST_VOTED_HEIGHT during pruning.
    // The highest voted height represents the historical maximum height an FP has voted on,
    // which should never decrease just because we delete old signature data for storage efficiency.

    Ok(all_signatures.len())
}

/// Prunes old signatories by block hash for all blocks.
///
/// This function removes all signatories entries for rollup blocks with height <= rollup_height.
/// It's designed to be called manually by the admin to prevent indefinite storage growth.
///
/// The function prunes up to `max_signatories_to_prune` old entries per call
/// to prevent gas exhaustion when there are many old entries to clean up.
///
/// # Arguments
///
/// * `storage` - The storage instance to operate on
/// * `rollup_height` - Remove all signatories for rollup blocks with height <= this value
/// * `max_signatories_to_prune` - Maximum number of signatories entries to prune in this operation
///     - If not provided, the default value is 50.
///     - If provided, the value must be between 1 and 100.
///
/// # Returns
///
/// Returns the number of signatories entries that were pruned, or an error if the operation failed.
pub(crate) fn prune_signatories_by_block_hash(
    storage: &mut dyn Storage,
    rollup_height: u64,
    max_signatories_to_prune: Option<u32>,
) -> Result<usize, ContractError> {
    let max_to_prune = max_signatories_to_prune
        .unwrap_or(DEFAULT_PRUNING)
        .min(MAX_PRUNING) as usize;

    // Get max signatories entries to prune in range from storage, ordered by height (ascending)
    let all_signatories = SIGNATORIES_BY_BLOCK_HASH
        .range(
            storage,
            None,
            Some(Bound::exclusive((rollup_height + 1, &[] as &[u8]))),
            cosmwasm_std::Order::Ascending,
        )
        .take(max_to_prune)
        .collect::<cosmwasm_std::StdResult<Vec<_>>>()?;

    for (key, _signatories) in &all_signatories {
        let (height, block_hash) = key;
        // Remove the signatories entry from storage
        SIGNATORIES_BY_BLOCK_HASH.remove(storage, (*height, block_hash.as_slice()));
    }

    Ok(all_signatories.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;

    #[test]
    fn test_insert_finality_sig_and_signatory() {
        let mut deps = mock_dependencies();
        let height = get_random_u64();
        let block_hash = get_random_block_hash();
        let signature = get_random_block_hash();
        let fp_btc_pk = get_random_fp_pk();
        let fp_btc_pk_hex = hex::encode(fp_btc_pk.clone());

        // Insert the data
        insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            height,
            &block_hash,
            &signature,
        )
        .unwrap();

        // Verify finality signature was stored correctly
        let finality_sig_info = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(finality_sig_info.len(), 1);
        assert!(finality_sig_info
            .iter()
            .any(|sig| sig.finality_sig == signature && sig.block_hash == block_hash));

        // Verify signatory was added to the set
        let signatories = get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hash)
            .unwrap()
            .unwrap();
        assert!(signatories.contains(&fp_btc_pk_hex));
        assert_eq!(signatories.len(), 1);

        // Test case 1 (should fail): duplicate signatory for the same block
        // TODO: replace insert_signatory with insert_signatory_and_finality_sig after
        // resolving #44
        let result = insert_signatory(
            deps.as_mut().storage,
            height,
            &block_hash,
            &fp_btc_pk_hex.clone(),
        );
        assert_eq!(
            result,
            Err(ContractError::DuplicateSignatory(fp_btc_pk_hex.clone()))
        );

        // Test case 2 (should succeed): signing a different block hash at the same height
        let different_block_hash = get_random_block_hash();
        let different_signature = get_random_block_hash();
        let result = insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            height,
            &different_block_hash,
            &different_signature,
        );

        // This should succeed
        assert!(result.is_ok());

        // Verify both finality signatures are stored correctly
        let finality_sig_info = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(finality_sig_info.len(), 2);
        // Should contain both signatures
        assert!(finality_sig_info
            .iter()
            .any(|sig| sig.finality_sig == signature && sig.block_hash == block_hash));
        assert!(finality_sig_info
            .iter()
            .any(|sig| sig.finality_sig == different_signature
                && sig.block_hash == different_block_hash));

        // Verify signatory was added to the set for the new block hash
        let signatories =
            get_signatories_by_block_hash(deps.as_ref().storage, height, &different_block_hash)
                .unwrap()
                .unwrap();
        assert!(signatories.contains(&fp_btc_pk_hex));
        assert_eq!(signatories.len(), 1);
    }

    #[test]
    fn test_prune_finality_signatures() {
        let mut deps = mock_dependencies();
        let fp_btc_pk1 = get_random_fp_pk();
        let fp_btc_pk2 = get_random_fp_pk();

        // Insert several finality signatures at different heights
        let heights = vec![100, 200, 300, 400, 500];
        let block_hashes: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();
        let signatures: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();

        // Insert signatures for first finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk1,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Insert signatures for second finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk2,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Verify signatures exist before pruning
        for &height in &heights {
            let sig1 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk1).unwrap();
            assert!(sig1.is_some());
            let sig2 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk2).unwrap();
            assert!(sig2.is_some());
        }

        // Test pruning with rollup_height = 250
        // This should prune signatures at heights 100, 200 for both finality providers
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 250, None).unwrap();
        assert_eq!(pruned_count, 4); // 2 signatures per FP = 4 total

        // Verify old signatures are gone
        for &height in &[100, 200] {
            let sig1 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk1).unwrap();
            assert!(sig1.is_none());
            let sig2 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk2).unwrap();
            assert!(sig2.is_none());
        }

        // Verify recent signatures are still there
        for &height in &[300, 400, 500] {
            let sig1 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk1).unwrap();
            assert!(sig1.is_some());
            let sig2 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk2).unwrap();
            assert!(sig2.is_some());
        }

        // Test pruning with a very low height (should prune nothing)
        let pruned_count2 = prune_finality_signatures(deps.as_mut().storage, 50, None).unwrap();
        assert_eq!(pruned_count2, 0);

        // Verify signatures are still there
        for &height in &[300, 400, 500] {
            let sig1 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk1).unwrap();
            assert!(sig1.is_some());
            let sig2 =
                list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk2).unwrap();
            assert!(sig2.is_some());
        }
    }

    #[test]
    fn test_prune_finality_signatures_with_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert many signatures
        let heights: Vec<u64> = (100..150).collect(); // 50 signatures
        let block_hashes: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();
        let signatures: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();

        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Test pruning with a limit of 10 (should only prune 10 signatures)
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 200, Some(10)).unwrap();
        assert_eq!(pruned_count, 10);

        // Verify only first 10 signatures are gone
        for &height in &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109] {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_none());
        }

        // Verify remaining signatures are still there
        for &height in &[110, 111, 112, 113, 114, 115, 116, 117, 118, 119] {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_some());
        }
    }

    #[test]
    fn test_prune_finality_signatures_empty_storage() {
        let mut deps = mock_dependencies();

        // Test pruning on empty storage
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 1000, None).unwrap();
        assert_eq!(pruned_count, 0);
    }

    #[test]
    fn test_prune_finality_signatures_max_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert some signatures
        for height in 100..110 {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Test with max limit (30) - should respect the limit
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 200, Some(50)).unwrap();
        assert_eq!(pruned_count, 10); // Only 10 signatures exist, all should be pruned

        // Verify all signatures are gone
        for height in 100..110 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_none());
        }
    }

    #[test]
    fn test_prune_finality_signatures_exact_height() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert signatures at specific heights
        let heights = vec![100, 200, 300];
        for &height in &heights {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Test pruning at exact height 200 (should include height 200)
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 200, None).unwrap();
        assert_eq!(pruned_count, 2); // Heights 100 and 200

        // Verify heights 100 and 200 are gone
        for &height in &[100, 200] {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_none());
        }

        // Verify height 300 is still there
        let sig = list_finality_signatures(deps.as_ref().storage, 300, &fp_btc_pk).unwrap();
        assert!(sig.is_some());
    }

    #[test]
    fn test_prune_signatories_by_block_hash() {
        let mut deps = mock_dependencies();
        let fp_btc_pk1 = get_random_fp_pk();
        let fp_btc_pk2 = get_random_fp_pk();

        // Insert several signatories entries at different heights
        let heights = vec![100, 200, 300, 400, 500];
        let block_hashes: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();
        let signatures: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();

        // Insert signatories for first finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk1,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Insert signatories for second finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk2,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Verify signatories exist before pruning
        for &height in &heights {
            let signatories1 = get_signatories_by_block_hash(
                deps.as_ref().storage,
                height,
                &block_hashes[heights.iter().position(|&h| h == height).unwrap()],
            )
            .unwrap();
            assert!(signatories1.is_some());
            let signatories2 = get_signatories_by_block_hash(
                deps.as_ref().storage,
                height,
                &block_hashes[heights.iter().position(|&h| h == height).unwrap()],
            )
            .unwrap();
            assert!(signatories2.is_some());
        }

        // Test pruning with rollup_height = 250
        // This should prune signatories at heights 100, 200 for both finality providers
        let pruned_count =
            prune_signatories_by_block_hash(deps.as_mut().storage, 250, None).unwrap();
        assert_eq!(pruned_count, 2); // 2 entries (one per block hash at heights 100, 200)

        // Verify old signatories are gone
        for &height in &[100, 200] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_none());
        }

        // Verify remaining signatories are still there
        for &height in &[300, 400, 500] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_some());
        }
    }

    #[test]
    fn test_prune_signatories_by_block_hash_with_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert many signatories entries
        let heights: Vec<u64> = (100..120).collect();
        let block_hashes: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();
        let signatures: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();

        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Test pruning with a limit of 5
        let pruned_count =
            prune_signatories_by_block_hash(deps.as_mut().storage, 150, Some(5)).unwrap();
        assert_eq!(pruned_count, 5); // Should only prune 5 entries due to limit

        // Verify only the first 5 heights are pruned
        for &height in &[100, 101, 102, 103, 104] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_none());
        }

        // Verify remaining heights are still there
        for &height in &[105, 106, 107, 108, 109] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_some());
        }
    }

    #[test]
    fn test_prune_signatories_by_block_hash_empty_storage() {
        let mut deps = mock_dependencies();

        // Test pruning on empty storage
        let pruned_count =
            prune_signatories_by_block_hash(deps.as_mut().storage, 100, None).unwrap();
        assert_eq!(pruned_count, 0);
    }

    #[test]
    fn test_prune_signatories_by_block_hash_max_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert many signatories entries
        let heights: Vec<u64> = (100..200).collect();
        let block_hashes: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();
        let signatures: Vec<Vec<u8>> = heights.iter().map(|_| get_random_block_hash()).collect();

        for (i, &height) in heights.iter().enumerate() {
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hashes[i],
                &signatures[i],
            )
            .unwrap();
        }

        // Test pruning with a limit higher than MAX_PRUNING
        let pruned_count =
            prune_signatories_by_block_hash(deps.as_mut().storage, 150, Some(200)).unwrap();
        assert_eq!(pruned_count, 51); // Should prune all 51 entries up to height 150

        // Verify all heights up to 150 are pruned
        for &height in &heights[..51] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_none());
        }

        // Verify remaining heights are still there
        for &height in &heights[51..] {
            let idx = heights.iter().position(|&h| h == height).unwrap();
            let signatories =
                get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hashes[idx])
                    .unwrap();
            assert!(signatories.is_some());
        }
    }

    #[test]
    fn test_highest_voted_height_basic() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Initially, no highest voted height should exist
        let result = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk).unwrap();
        assert!(result.is_none());

        // Insert finality signatures at different heights (not in order)
        let heights = vec![100, 150, 120, 200, 180];
        for &height in &heights {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();

            // After each insertion, verify the highest voted height is correct
            let current_highest = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
                .unwrap()
                .unwrap();
            
            let expected_highest = heights[..heights.iter().position(|&h| h == height).unwrap() + 1]
                .iter()
                .max()
                .unwrap();
            assert_eq!(current_highest, *expected_highest);
        }

        // Final highest should be 200
        let final_highest = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(final_highest, 200);
    }

    #[test]
    fn test_highest_voted_height_multiple_fps() {
        let mut deps = mock_dependencies();
        let fp_btc_pk1 = get_random_fp_pk();
        let fp_btc_pk2 = get_random_fp_pk();

        // Insert signatures for first FP
        for &height in &[100, 150, 200] {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk1,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Insert signatures for second FP at different heights
        for &height in &[50, 75, 90] {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk2,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Verify each FP has correct highest voted height
        let highest1 = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk1)
            .unwrap()
            .unwrap();
        assert_eq!(highest1, 200);

        let highest2 = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk2)
            .unwrap()
            .unwrap();
        assert_eq!(highest2, 90);

        // Third FP should have no highest voted height
        let fp_btc_pk3 = get_random_fp_pk();
        let result3 = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk3).unwrap();
        assert!(result3.is_none());
    }

    #[test]
    fn test_highest_voted_height_with_pruning() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert finality signatures at different heights
        let heights = vec![100, 150, 200, 250, 300];
        for &height in &heights {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Verify highest is 300
        let highest = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest, 300);

        // Prune signatures up to height 200 (inclusive)
        let pruned_count = prune_finality_signatures(deps.as_mut().storage, 200, None).unwrap();
        assert_eq!(pruned_count, 3); // Should prune heights 100, 150, 200

        // Highest should still be 300 (since 250, 300 remain)
        let highest_after_prune = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest_after_prune, 300);

        // Prune signatures up to height 275 (should remove 250)
        let pruned_count2 = prune_finality_signatures(deps.as_mut().storage, 275, None).unwrap();
        assert_eq!(pruned_count2, 1); // Should prune height 250

        // Highest should still be 300
        let highest_after_prune2 = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest_after_prune2, 300);

        // Prune all remaining signatures
        let pruned_count3 = prune_finality_signatures(deps.as_mut().storage, 350, None).unwrap();
        assert_eq!(pruned_count3, 1); // Should prune height 300

        // Highest voted height should still be 300 (historical maximum preserved)
        let result = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk).unwrap();
        assert_eq!(result.unwrap(), 300);
    }

    #[test]
    fn test_highest_voted_height_multiple_signatures_same_height() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        let height = 100;
        
        // Insert multiple signatures at the same height (different block hashes)
        // This simulates voting on different forks at the same height
        for _ in 0..3 {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // The highest voted height should be 100
        let highest = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest, height);

        // Add signature at higher height
        let higher_height = 150;
        let block_hash = get_random_block_hash();
        let signature = get_random_block_hash();
        insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            higher_height,
            &block_hash,
            &signature,
        )
        .unwrap();

        // Highest should now be 150
        let highest_after = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest_after, higher_height);
    }

    #[test]
    fn test_highest_voted_height_edge_cases() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Test with height 0
        let block_hash = get_random_block_hash();
        let signature = get_random_block_hash();
        insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            0,
            &block_hash,
            &signature,
        )
        .unwrap();

        let highest = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest, 0);

        // Test with maximum u64 height
        let max_height = u64::MAX;
        let block_hash2 = get_random_block_hash();
        let signature2 = get_random_block_hash();
        insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            max_height,
            &block_hash2,
            &signature2,
        )
        .unwrap();

        let highest_max = get_highest_voted_height(deps.as_ref().storage, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(highest_max, max_height);
    }
}
