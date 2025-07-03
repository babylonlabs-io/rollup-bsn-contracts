use crate::error::ContractError;
use crate::state::Bytes;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::{Bound, Map};

/// Map of public randomness values by fp public key hex and block height
pub(crate) const PUB_RAND_VALUES: Map<(&str, u64), Vec<u8>> = Map::new("pub_rand_values");

/// Map of public randomness commitments by fp and block height
pub(crate) const PUB_RAND_COMMITS: Map<(&str, u64), PubRandCommit> = Map::new("pub_rand_commits");

/// `PubRandCommit` is a commitment to a series of public randomness.
/// Currently, the commitment is a root of a Merkle tree that includes a series of public randomness
/// values
#[cw_serde]
pub struct PubRandCommit {
    /// `start_height` is the height of the first commitment
    pub start_height: u64,
    /// `num_pub_rand` is the number of committed public randomness
    pub num_pub_rand: u64,
    /// `height` defines the height that the commit was submitted
    pub height: u64,
    /// `commitment` is the value of the commitment.
    /// Currently, it's the root of the Merkle tree constructed by the public randomness
    pub commitment: Bytes,
}

impl PubRandCommit {
    /// `in_range` checks if the given height is within the range of the commitment
    pub fn in_range(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height()
    }

    /// `end_height` returns the height of the last commitment
    pub fn end_height(&self) -> u64 {
        self.start_height + self.num_pub_rand - 1
    }
}

// Copied from contracts/btc-staking/src/state/public_randomness.rs
pub fn get_pub_rand_commit_for_height(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let end_at = Some(Bound::inclusive(height));
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
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
            fp_btc_pk_hex.to_string(),
            height,
        ))
    } else {
        Ok(res[0].clone())
    }
}

// Copied from contracts/btc-staking/src/state/public_randomness.rs
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn get_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
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
        .prefix(fp_btc_pk_hex)
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

/// Inserts a public randomness value into the PUB_RAND_VALUES map for the given fp and height.
///
/// - If no value exists, it inserts the value.
/// - If the same value already exists, it is a no-op and returns Ok(())
/// - If a different value exists, it returns ContractError::PubRandAlreadyExists.
///   This is an error as the contract should recognize only a single public randomness value
///   for a specific height per finality provider.
pub fn insert_pub_rand_value(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
    height: u64,
    pub_rand: &[u8],
) -> Result<(), ContractError> {
    if let Some(existing) = PUB_RAND_VALUES.may_load(storage, (fp_btc_pk_hex, height))? {
        if existing == pub_rand {
            return Ok(());
        } else {
            return Err(ContractError::PubRandAlreadyExists(
                fp_btc_pk_hex.to_string(),
                height,
            ));
        }
    }
    PUB_RAND_VALUES.save(storage, (fp_btc_pk_hex, height), &pub_rand.to_vec())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_insert_pub_rand_value() {
        let mut deps = mock_dependencies();
        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let num_sets = thread_rng().gen_range(1..=5);
        let mut all_heights = std::collections::HashSet::new();
        let mut pub_rands = Vec::new();
        let mut last_height = 0u64;
        for _ in 0..num_sets {
            let set_len = thread_rng().gen_range(1..=10);
            // Ensure a gap of at least 1 between sets
            let start_height = last_height + thread_rng().gen_range(1..=5);
            let heights: Vec<u64> = (start_height..start_height + set_len).collect();
            for &height in &heights {
                assert!(!all_heights.contains(&height), "Height overlap detected");
                all_heights.insert(height);
                let pub_rand = get_random_pub_rand();
                insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk_hex, height, &pub_rand)
                    .unwrap();
                pub_rands.push((height, pub_rand.clone()));
            }
            last_height = *heights.last().unwrap();
        }
        // Check that all pub_rand values are present
        for (height, pub_rand) in &pub_rands {
            let stored = PUB_RAND_VALUES
                .load(deps.as_ref().storage, (&fp_btc_pk_hex, *height))
                .unwrap();
            assert_eq!(stored, *pub_rand);
            // Try to insert the same value again and expect Ok(())
            assert!(insert_pub_rand_value(
                deps.as_mut().storage,
                &fp_btc_pk_hex,
                *height,
                pub_rand
            )
            .is_ok());
            // Try to insert a different value and expect an error
            let mut different_pub_rand = get_random_pub_rand();
            // Ensure it's different
            while different_pub_rand == *pub_rand {
                different_pub_rand = get_random_pub_rand();
            }
            let err = insert_pub_rand_value(
                deps.as_mut().storage,
                &fp_btc_pk_hex,
                *height,
                &different_pub_rand,
            )
            .unwrap_err();
            match err {
                ContractError::PubRandAlreadyExists(ref pk, h) => {
                    assert_eq!(pk, &fp_btc_pk_hex);
                    assert_eq!(h, *height);
                }
                _ => panic!("Expected PubRandAlreadyExists error, got {:?}", err),
            }
        }
    }
}
