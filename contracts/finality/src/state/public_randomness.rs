use cosmwasm_schema::cw_serde;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdResult, Storage};

use cw_storage_plus::{Bound, Map};

use babylon_bindings::BabylonQuery;

use crate::custom_queries::get_last_finalized_epoch;
use crate::error::ContractError;
use crate::state::Bytes;

/// Map of public randomness commitments by fp and block height
pub(crate) const PUB_RAND_COMMITS: Map<(&str, u64), PubRandCommit> = Map::new("pub_rand_commits");
/// Map of public randomness values by fp and block height
pub(crate) const PUB_RAND_VALUES: Map<(&str, u64), Vec<u8>> = Map::new("pub_rand_values");

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
    pub epoch: u64,
    /// Value of the commitment.
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

// Finds the public randomness commitment that includes the given height for the given finality
// provider.
// It also checks that the commitment is timestamped by BTC, meaning that the epoch of the
// commitment is less than or equal to the last finalized epoch.
pub fn get_timestamped_pub_rand_commit_for_height(
    deps: &Deps<BabylonQuery>,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height)?;

    // Ensure the finality provider's corresponding randomness commitment is already finalised by
    // BTC timestamping
    let last_finalized_epoch = get_last_finalized_epoch(deps)?;
    if last_finalized_epoch == 0 {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(
            "No finalized epoch yet".into(),
        ));
    }
    if last_finalized_epoch < pr_commit.epoch {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(format!(
            "The finality provider {0} last committed epoch: {1}, last finalized epoch: {2}",
            fp_btc_pk_hex, pr_commit.epoch, last_finalized_epoch
        )));
    }

    Ok(pr_commit)
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
