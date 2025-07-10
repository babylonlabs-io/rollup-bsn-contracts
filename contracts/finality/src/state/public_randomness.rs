use crate::custom_queries::get_last_finalized_epoch;
use crate::error::ContractError;
use crate::state::Bytes;
use babylon_bindings::BabylonQuery;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_storage_plus::{Bound, Map};

/// Map of public randomness values by fp public key and block height
const PUB_RAND_VALUES: Map<(&[u8], u64), Vec<u8>> = Map::new("pub_rand_values");

/// Gets a public randomness value from the PUB_RAND_VALUES map.
pub(crate) fn get_pub_rand_value(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<Option<Vec<u8>>, ContractError> {
    PUB_RAND_VALUES
        .may_load(storage, (fp_btc_pk, height))
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

fn get_pub_rand_commit_for_height(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
) -> Result<PubRandCommit, ContractError> {
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
        Err(ContractError::MissingPubRandCommit(
            hex::encode(fp_btc_pk),
            height,
        ))
    } else {
        Ok(res[0].clone())
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
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk, height)?;

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

pub fn get_pub_rand_commit(
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
    PUB_RAND_VALUES.save(storage, (fp_btc_pk, height), &pub_rand.to_vec())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use rand::{rng, Rng};

    #[test]
    fn insert_pub_rand_commit_works() {
        let mut deps = mock_dependencies();
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

        // Test the new get_pub_rand_commit function (used by ListPubRandCommit query)
        let list_result = get_pub_rand_commit(deps.as_ref().storage, &fp_btc_pk, None, None, None).unwrap();
        assert_eq!(list_result.len(), 1);
        assert_eq!(list_result[0], valid_commit);

        // Test with different pagination parameters
        let limited_result = get_pub_rand_commit(deps.as_ref().storage, &fp_btc_pk, None, Some(5), None).unwrap();
        assert_eq!(limited_result.len(), 1);
        assert_eq!(limited_result[0], valid_commit);

        // Test with reverse ordering
        let reverse_result = get_pub_rand_commit(deps.as_ref().storage, &fp_btc_pk, None, None, Some(true)).unwrap();
        assert_eq!(reverse_result.len(), 1);
        assert_eq!(reverse_result[0], valid_commit);

        // Test with non-existent FP (should return empty)
        let other_fp_pk = get_random_fp_pk();
        let empty_result = get_pub_rand_commit(deps.as_ref().storage, &other_fp_pk, None, None, None).unwrap();
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
}
