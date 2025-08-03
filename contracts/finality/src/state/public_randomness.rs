use crate::custom_queries::get_last_finalized_epoch;
use crate::error::ContractError;
use crate::state::pruning::{DEFAULT_PRUNING, MAX_PRUNING};
use crate::state::Bytes;
use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_storage_plus::{Bound, Map};

/// Map of public randomness values by block height and fp public key
const PUB_RAND_VALUES: Map<(u64, &[u8]), Vec<u8>> = Map::new("pub_rand_values");

/// Gets a public randomness value from the PUB_RAND_VALUES map.
pub(crate) fn get_pub_rand_value(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<Option<Vec<u8>>, ContractError> {
    PUB_RAND_VALUES
        .may_load(storage, (height, fp_btc_pk))
        .map_err(|_| ContractError::FailedToLoadPubRand(hex::encode(fp_btc_pk), height))
}

/// Map of public randomness commitments by fp public key and block height
const PUB_RAND_COMMITS: Map<(&[u8], u64), PubRandCommit> = Map::new("pub_rand_commits");

/// `PubRandCommit` is a commitment to a series of public randomness.
/// Currently, the commitment is a root of a Merkle tree that includes a series of public randomness
/// values
#[cw_serde]
pub struct PubRandCommit {
    /// The height of the first commitment
    pub start_height: u64,
    /// The amount of committed public randomness
    pub num_pub_rand: u64,
    /// The epoch number of Babylon when the commit was submitted
    pub babylon_epoch: u64,
    /// Value of the commitment.
    /// Currently, it's the root of the Merkle tree constructed by the public randomness
    pub commitment: Bytes,
}

impl PubRandCommit {
    pub fn new(start_height: u64, num_pub_rand: u64, epoch: u64, commitment: Bytes) -> Self {
        Self {
            start_height,
            num_pub_rand,
            babylon_epoch: epoch,
            commitment,
        }
    }

    /// `in_range` checks if the given height is within the range of the commitment
    pub fn in_range(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height()
    }

    /// `end_height` returns the height of the last commitment
    pub fn end_height(&self) -> u64 {
        self.start_height + self.num_pub_rand - 1
    }
}

pub fn get_pub_rand_commit_for_height(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<Option<PubRandCommit>, ContractError> {
    let end_at = Some(Bound::inclusive(height));
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk)
        .range_raw(storage, None, end_at, Descending)
        .filter(|item| {
            match item {
                Ok((_, value)) => value.in_range(height),
                Err(_) => true, // if we can't parse, we keep it
            }
        })
        .take(1)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;
    if res.is_empty() {
        Ok(None)
    } else {
        Ok(Some(res[0].clone()))
    }
}

// Finds the public randomness commitment that includes the given height for the given finality
// provider.
// It also checks that the commitment is timestamped by BTC, meaning that the epoch of the
// commitment is less than or equal to the last finalized epoch.
pub fn get_timestamped_pub_rand_commit_for_height(
    deps: &Deps<BabylonQuery>,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk, height)?
        .ok_or_else(|| ContractError::MissingPubRandCommit(hex::encode(fp_btc_pk), height))?;

    // Ensure the finality provider's corresponding randomness commitment is already finalised by
    // BTC timestamping
    let last_finalized_epoch = get_last_finalized_epoch(deps)?;
    if last_finalized_epoch == 0 {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(
            "No finalized epoch yet".into(),
        ));
    }
    if last_finalized_epoch < pr_commit.babylon_epoch {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(format!(
            "The finality provider {0} last committed epoch: {1}, last finalized epoch: {2}",
            hex::encode(fp_btc_pk),
            pr_commit.babylon_epoch,
            last_finalized_epoch
        )));
    }

    Ok(pr_commit)
}

const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

fn get_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    start_after: Option<u64>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<PubRandCommit>, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk)
        .range_raw(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;

    // Return the results or an empty vector if no results found
    Ok(res)
}

pub fn list_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    start_after: Option<u64>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk, start_after, limit, reverse)?;
    Ok(res)
}

pub fn get_first_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk, None, Some(1), Some(false))?;
    Ok(res.into_iter().next())
}

pub fn get_last_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk, None, Some(1), Some(true))?;
    Ok(res.into_iter().next())
}

/// `insert_pub_rand_commit` inserts a public randomness commitment into the storage.
/// It ensures that the new commitment does not overlap with the existing ones.
pub fn insert_pub_rand_commit(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    pr_commit: PubRandCommit,
) -> Result<(), ContractError> {
    // Get last public randomness commitment
    let last_pr_commit = get_last_pub_rand_commit(storage, fp_btc_pk)?;

    // Ensure height and start_height do not overlap, i.e., height < start_height
    if let Some(last_pr_commit) = last_pr_commit {
        let last_pr_end_height = last_pr_commit.end_height();
        if pr_commit.start_height <= last_pr_end_height {
            return Err(ContractError::InvalidPubRandHeight(
                pr_commit.start_height,
                last_pr_end_height,
            ));
        }
    }

    // All good, store the given public randomness commitment
    PUB_RAND_COMMITS.save(storage, (fp_btc_pk, pr_commit.start_height), &pr_commit)?;
    Ok(())
}

/// Inserts a public randomness value into the PUB_RAND_VALUES map for the given fp and height.
///
/// - If no value exists, it inserts the value.
/// - If the same value already exists, it is a no-op and returns Ok(())
/// - If a different value exists, it returns ContractError::PubRandAlreadyExists.
///   This is an error as the contract should recognize only a single public randomness value
///   for a specific height per finality provider.
pub(crate) fn insert_pub_rand_value(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
    pub_rand: &[u8],
) -> Result<(), ContractError> {
    if let Some(existing) = get_pub_rand_value(storage, fp_btc_pk, height)? {
        if existing == pub_rand {
            return Ok(());
        } else {
            return Err(ContractError::PubRandAlreadyExists(
                hex::encode(fp_btc_pk),
                height,
            ));
        }
    }
    PUB_RAND_VALUES.save(storage, (height, fp_btc_pk), &pub_rand.to_vec())?;
    Ok(())
}

/// Prunes old public randomness values for all finality providers.
///
/// This function removes all public randomness values for rollup blocks with height <= rollup_height.
/// It's designed to be called manually by the admin to prevent indefinite storage growth.
///
/// The function prunes up to `max_values_to_prune` old values per call
/// to prevent gas exhaustion when there are many old values to clean up.
///
/// # Arguments
///
/// * `storage` - The storage instance to operate on
/// * `rollup_height` - Remove all values for rollup blocks with height <= this value
/// * `max_values_to_prune` - Maximum number of values to prune in this operation
///     - If not provided, the default value is 20.
///     - If provided, the value must be between 1 and 50.
///
/// # Returns
///
/// Returns the number of values that were pruned, or an error if the operation failed.
pub(crate) fn prune_public_randomness_values(
    storage: &mut dyn Storage,
    rollup_height: u64,
    max_values_to_prune: Option<u32>,
) -> Result<usize, ContractError> {
    let max_to_prune = max_values_to_prune
        .unwrap_or(DEFAULT_PRUNING)
        .min(MAX_PRUNING) as usize;

    // Get max public randomness values to prune in range from storage, ordered by height (ascending)
    let all_values = PUB_RAND_VALUES
        .range(
            storage,
            None,
            Some(Bound::exclusive((rollup_height + 1, &[] as &[u8]))),
            cosmwasm_std::Order::Ascending,
        )
        .take(max_to_prune)
        .collect::<cosmwasm_std::StdResult<Vec<_>>>()?;

    for (key, _pub_rand_value) in &all_values {
        let (height, fp_btc_pk) = key;
        // Remove the value from storage
        PUB_RAND_VALUES.remove(storage, (*height, fp_btc_pk.as_slice()));
    }

    Ok(all_values.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use rand::{rng, Rng};

    #[test]
    fn insert_pub_rand_commit_works() {
        use crate::contract::query;
        use crate::contract::tests::mock_deps_babylon;
        use crate::msg::QueryMsg;
        use cosmwasm_std::{from_json, testing::mock_env};

        let mut deps = mock_deps_babylon();
        let env = mock_env();
        let fp_btc_pk = get_random_fp_pk();
        let start_height = get_random_u64();
        let commitment = get_random_block_hash();

        // Test with valid num_pub_rand (should pass)
        let valid_commit = PubRandCommit::new(
            start_height,
            1, // Valid value should pass
            env.block.height,
            commitment,
        );

        let result =
            insert_pub_rand_commit(deps.as_mut().storage, &fp_btc_pk, valid_commit.clone());

        // Should pass
        assert!(result.is_ok());

        // Verify we can retrieve it with the helper functions
        let first_commit = get_first_pub_rand_commit(deps.as_ref().storage, &fp_btc_pk).unwrap();
        assert_eq!(first_commit.unwrap(), valid_commit);
        let last_commit = get_last_pub_rand_commit(deps.as_ref().storage, &fp_btc_pk).unwrap();
        assert_eq!(last_commit.unwrap(), valid_commit);

        // Test the ListPubRandCommit query end-to-end
        let list_result: Vec<PubRandCommit> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ListPubRandCommit {
                    btc_pk_hex: hex::encode(&fp_btc_pk),
                    start_after: None,
                    limit: Some(10),
                    reverse: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(list_result.len(), 1);
        assert_eq!(list_result[0], valid_commit);

        // Test with non-existent FP (should return empty)
        let other_fp_pk = get_random_fp_pk();
        let empty_result: Vec<PubRandCommit> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ListPubRandCommit {
                    btc_pk_hex: hex::encode(&other_fp_pk),
                    start_after: None,
                    limit: None,
                    reverse: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(empty_result.len(), 0);
    }

    #[test]
    fn insert_pub_rand_commit_height_overlap_validation() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // === SETUP: First commitment ===
        let fp_btc_pk = get_random_fp_pk();
        let initial_start_height = get_random_u64();
        let initial_num_pub_rand = get_random_u64();
        let initial_commitment = get_random_block_hash();

        // Store initial commitment directly
        let initial_commit = &PubRandCommit::new(
            initial_start_height,
            initial_num_pub_rand,
            env.block.height,
            initial_commitment,
        );
        insert_pub_rand_commit(deps.as_mut().storage, &fp_btc_pk, initial_commit.clone()).unwrap();

        // === TEST CASE 1: Overlapping start height (should fail) ===
        let overlapping_start_height = initial_start_height - 1;
        let overlapping_num_pub_rand = get_random_u64();
        let overlapping_commitment = get_random_block_hash();

        let overlapping_commit = PubRandCommit::new(
            overlapping_start_height,
            overlapping_num_pub_rand,
            env.block.height,
            overlapping_commitment,
        );

        let overlapping_result =
            insert_pub_rand_commit(deps.as_mut().storage, &fp_btc_pk, overlapping_commit);

        // Should fail due to overlap
        assert_eq!(
            overlapping_result,
            Err(ContractError::InvalidPubRandHeight(
                overlapping_start_height,
                initial_commit.end_height(),
            ))
        );

        // === TEST CASE 2: Exactly at boundary (should fail) ===
        let boundary_start_height = initial_commit.end_height();
        let boundary_num_pub_rand = get_random_u64();
        let boundary_commitment = get_random_block_hash();

        let boundary_commit = PubRandCommit::new(
            boundary_start_height,
            boundary_num_pub_rand,
            env.block.height,
            boundary_commitment,
        );

        let boundary_result =
            insert_pub_rand_commit(deps.as_mut().storage, &fp_btc_pk, boundary_commit);

        // Should fail due to boundary overlap
        assert_eq!(
            boundary_result,
            Err(ContractError::InvalidPubRandHeight(
                initial_commit.end_height(),
                initial_commit.end_height()
            ))
        );

        // === TEST CASE 3: Valid non-overlapping commitment (should pass height validation) ===
        let valid_start_height = initial_start_height + initial_num_pub_rand;
        let valid_num_pub_rand = get_random_u64();
        let valid_commitment = get_random_block_hash();

        let valid_commit = PubRandCommit::new(
            valid_start_height,
            valid_num_pub_rand,
            env.block.height,
            valid_commitment,
        );

        let valid_result = insert_pub_rand_commit(deps.as_mut().storage, &fp_btc_pk, valid_commit);

        // Should pass height overlap validation
        assert!(valid_result.is_ok());
    }

    #[test]
    fn test_insert_pub_rand_value() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();
        let num_sets = rng().random_range(1..=5);
        let mut all_heights = std::collections::HashSet::new();
        let mut pub_rands = Vec::new();
        let mut last_height = 0u64;
        for _ in 0..num_sets {
            let set_len = rng().random_range(1..=10);
            // Ensure a gap of at least 1 between sets
            let start_height = last_height + rng().random_range(1..=5);
            let heights: Vec<u64> = (start_height..start_height + set_len).collect();
            for &height in &heights {
                assert!(!all_heights.contains(&height), "Height overlap detected");
                all_heights.insert(height);
                let pub_rand = get_random_pub_rand();
                insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk.clone(), height, &pub_rand)
                    .unwrap();
                pub_rands.push((height, pub_rand.clone()));
            }
            last_height = *heights.last().unwrap();
        }
        // Check that all pub_rand values are present
        for (height, pub_rand) in &pub_rands {
            let fp_btc_pk = fp_btc_pk.clone();
            let stored = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, *height)
                .unwrap()
                .unwrap();
            assert_eq!(stored, *pub_rand);
            // Try to insert the same value again and expect Ok(())
            assert!(
                insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, *height, pub_rand).is_ok()
            );
            // Try to insert a different value and expect an error
            let mut different_pub_rand = get_random_pub_rand();
            // Ensure it's different
            while different_pub_rand == *pub_rand {
                different_pub_rand = get_random_pub_rand();
            }
            let err = insert_pub_rand_value(
                deps.as_mut().storage,
                &fp_btc_pk,
                *height,
                &different_pub_rand,
            )
            .unwrap_err();
            match err {
                ContractError::PubRandAlreadyExists(ref pk, h) => {
                    assert_eq!(pk, &hex::encode(fp_btc_pk));
                    assert_eq!(h, *height);
                }
                _ => panic!("Expected PubRandAlreadyExists error, got {err:?}"),
            }
        }
    }

    #[test]
    fn test_prune_public_randomness_values() {
        let mut deps = mock_dependencies();
        let fp_btc_pk1 = get_random_fp_pk();
        let fp_btc_pk2 = get_random_fp_pk();

        // Insert several public randomness values at different heights
        let heights = vec![100, 200, 300, 400, 500];
        let pub_rands: Vec<Vec<u8>> = heights.iter().map(|_| get_random_pub_rand()).collect();

        // Insert values for first finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk1, height, &pub_rands[i])
                .unwrap();
        }

        // Insert values for second finality provider
        for (i, &height) in heights.iter().enumerate() {
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk2, height, &pub_rands[i])
                .unwrap();
        }

        // Verify values exist before pruning
        for &height in &heights {
            let val1 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk1, height).unwrap();
            assert!(val1.is_some());
            let val2 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk2, height).unwrap();
            assert!(val2.is_some());
        }

        // Test pruning with rollup_height = 250
        // This should prune values at heights 100, 200 for both finality providers
        let pruned_count =
            prune_public_randomness_values(deps.as_mut().storage, 250, None).unwrap();
        assert_eq!(pruned_count, 4); // 2 values per FP = 4 total

        // Verify old values are gone
        for &height in &[100, 200] {
            let val1 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk1, height).unwrap();
            assert!(val1.is_none());
            let val2 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk2, height).unwrap();
            assert!(val2.is_none());
        }

        // Verify recent values are still there
        for &height in &[300, 400, 500] {
            let val1 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk1, height).unwrap();
            assert!(val1.is_some());
            let val2 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk2, height).unwrap();
            assert!(val2.is_some());
        }

        // Test pruning with a very low height (should prune nothing)
        let pruned_count2 =
            prune_public_randomness_values(deps.as_mut().storage, 50, None).unwrap();
        assert_eq!(pruned_count2, 0);

        // Verify values are still there
        for &height in &[300, 400, 500] {
            let val1 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk1, height).unwrap();
            assert!(val1.is_some());
            let val2 = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk2, height).unwrap();
            assert!(val2.is_some());
        }
    }

    #[test]
    fn test_prune_public_randomness_values_with_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert many values
        let heights: Vec<u64> = (100..150).collect(); // 50 values
        let pub_rands: Vec<Vec<u8>> = heights.iter().map(|_| get_random_pub_rand()).collect();

        for (i, &height) in heights.iter().enumerate() {
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, height, &pub_rands[i])
                .unwrap();
        }

        // Test pruning with a limit of 10 (should only prune 10 values)
        let pruned_count =
            prune_public_randomness_values(deps.as_mut().storage, 200, Some(10)).unwrap();
        assert_eq!(pruned_count, 10);

        // Verify only first 10 values are gone
        for &height in &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109] {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_none());
        }

        // Verify remaining values are still there
        for &height in &[110, 111, 112, 113, 114, 115, 116, 117, 118, 119] {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_some());
        }
    }

    #[test]
    fn test_prune_public_randomness_values_empty_storage() {
        let mut deps = mock_dependencies();

        // Test pruning on empty storage
        let pruned_count =
            prune_public_randomness_values(deps.as_mut().storage, 1000, None).unwrap();
        assert_eq!(pruned_count, 0);
    }

    #[test]
    fn test_prune_public_randomness_values_max_limit() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert some values
        for height in 100..110 {
            let pub_rand = get_random_pub_rand();
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, height, &pub_rand).unwrap();
        }

        // Test with max limit (50) - should respect the limit
        let pruned_count =
            prune_public_randomness_values(deps.as_mut().storage, 200, Some(100)).unwrap();
        assert_eq!(pruned_count, 10); // Only 10 values exist, all should be pruned

        // Verify all values are gone
        for height in 100..110 {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_none());
        }
    }

    #[test]
    fn test_prune_public_randomness_values_exact_height() {
        let mut deps = mock_dependencies();
        let fp_btc_pk = get_random_fp_pk();

        // Insert values at specific heights
        let heights = vec![100, 200, 300];
        for &height in &heights {
            let pub_rand = get_random_pub_rand();
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, height, &pub_rand).unwrap();
        }

        // Test pruning at exact height 200 (should include height 200)
        let pruned_count =
            prune_public_randomness_values(deps.as_mut().storage, 200, None).unwrap();
        assert_eq!(pruned_count, 2); // Heights 100 and 200

        // Verify heights 100 and 200 are gone
        for &height in &[100, 200] {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_none());
        }

        // Verify height 300 is still there
        let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, 300).unwrap();
        assert!(val.is_some());
    }
}
