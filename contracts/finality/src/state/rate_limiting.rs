use crate::{error::ContractError, state::config::get_config};
use cosmwasm_std::{Env, Storage};

use cw_storage_plus::Map;

/// Stores the number of messages processed for each finality provider within the last block interval
/// Key: Finality Provider's BTC public key
/// Value: Tuple of (block interval number, message count)
const NUM_MSGS_LAST_INTERVAL: Map<&[u8], (u64, u32)> = Map::new("num_msgs_last_interval");

/// The number of blocks that define a rate limiting interval
const RATE_LIMIT_BLOCK_INTERVAL: u64 = 10000;

/// Increments the message counter for a finality provider and enforces rate limiting.
///
/// This function tracks the number of messages processed for each finality provider
/// within a block interval window. It increments the counter for the current interval and
/// resets it when a new interval begins.
///
/// # Arguments
/// * `storage` - Mutable reference to the contract's storage
/// * `fp_btc_pk` - The Bitcoin public key of the finality provider
/// * `env` - The environment containing block height information
///
/// # Returns
/// * `Ok(())` if the rate limit is not exceeded
/// * `Err(ContractError::RateLimitExceeded)` if adding one more message would exceed
///   the maximum allowed messages per interval (max_msgs_per_interval)
pub fn accumulate_rate_limiter(
    storage: &mut dyn Storage,
    env: &Env,
    fp_btc_pk: &[u8],
) -> Result<(), ContractError> {
    let current_block_height = env.block.height;
    let current_interval = current_block_height / RATE_LIMIT_BLOCK_INTERVAL;

    // Get existing record or initialize if it's a new FP or new interval
    let (interval, count) = NUM_MSGS_LAST_INTERVAL
        .may_load(storage, fp_btc_pk)?
        .unwrap_or((current_interval, 0));

    // Determine if it's a new interval and set the appropriate count
    let (new_interval, new_count) = if interval == current_interval {
        // Same interval, use existing count
        (interval, count + 1)
    } else {
        // New interval, reset count
        (current_interval, 1)
    };

    // Check if adding one more would exceed the limit
    let max_msgs_per_interval = get_config(storage)?.max_msgs_per_interval;
    if new_count > max_msgs_per_interval {
        return Err(ContractError::RateLimitExceeded {
            fp_btc_pk: hex::encode(fp_btc_pk),
            limit: max_msgs_per_interval,
        });
    }

    // Increment the counter and save
    NUM_MSGS_LAST_INTERVAL.save(storage, fp_btc_pk, &(new_interval, new_count))?;

    Ok(())
}
