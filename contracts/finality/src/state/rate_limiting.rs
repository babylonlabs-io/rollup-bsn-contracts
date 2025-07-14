use cosmwasm_std::{Storage, Timestamp};
use cw_storage_plus::Map;

use crate::{error::ContractError, state::config::get_config};

/// Stores the number of messages processed for each finality provider within the last hour
/// Key: Finality Provider's BTC public key
/// Value: Tuple of (hour number, message count)
const NUM_MSGS_LAST_HOUR: Map<&[u8], (u64, u32)> = Map::new("num_msgs_last_hour");

/// Increments the message counter for a finality provider and enforces rate limiting.
///
/// This function tracks the number of messages processed for each finality provider
/// within an hourly window. It increments the counter for the current hour and
/// resets it when a new hour begins.
///
/// # Arguments
/// * `storage` - Mutable reference to the contract's storage
/// * `fp_btc_pk` - The Bitcoin public key of the finality provider
/// * `current_time` - The current timestamp used to determine the hour
///
/// # Returns
/// * `Ok(())` if the rate limit is not exceeded
/// * `Err(ContractError::RateLimitExceeded)` if adding one more message would exceed
///   the maximum allowed messages per hour (MAX_MSGS_PER_HOUR)
pub fn accumulate_rate_limiter(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    current_time: Timestamp,
) -> Result<(), ContractError> {
    let current_hour = current_time.seconds() / 3600;

    // Get existing record or initialize if it's a new FP or new hour
    let (hour, count) = NUM_MSGS_LAST_HOUR
        .may_load(storage, fp_btc_pk)?
        .unwrap_or((current_hour, 0));

    // Determine if it's a new hour and set the appropriate count
    let (new_hour, new_count) = if hour == current_hour {
        // Same hour, use existing count
        (hour, count + 1)
    } else {
        // New hour, reset count
        (current_hour, 1)
    };

    // Check if adding one more would exceed the limit
    let max_msgs_per_hour = get_config(storage)?.max_msgs_per_hour;
    if new_count > max_msgs_per_hour {
        return Err(ContractError::RateLimitExceeded {
            fp_btc_pk: hex::encode(fp_btc_pk),
            limit: max_msgs_per_hour,
        });
    }

    // Increment the counter and save
    NUM_MSGS_LAST_HOUR.save(storage, fp_btc_pk, &(new_hour, new_count))?;

    Ok(())
}
