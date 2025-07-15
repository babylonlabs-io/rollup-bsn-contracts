use crate::{error::ContractError, state::config::get_config};
use cosmwasm_std::{Env, Storage};

use cw_storage_plus::Map;

/// Stores the number of messages processed for each finality provider within the last block interval
/// Key: Finality Provider's BTC public key
/// Value: Tuple of (block interval number, message count)
const NUM_MSGS_LAST_INTERVAL: Map<&[u8], (u64, u32)> = Map::new("num_msgs_last_interval");

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
pub fn check_rate_limit_and_accumulate(
    storage: &mut dyn Storage,
    env: &Env,
    fp_btc_pk: &[u8],
) -> Result<(), ContractError> {
    let rl_cfg = get_config(storage)?.rate_limiting;

    let current_block_height = env.block.height;
    let current_interval = current_block_height / rl_cfg.block_interval;

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
    if new_count > rl_cfg.max_msgs_per_interval {
        return Err(ContractError::RateLimitExceeded {
            fp_btc_pk: hex::encode(fp_btc_pk),
            limit: rl_cfg.max_msgs_per_interval,
        });
    }

    // Increment the counter and save
    NUM_MSGS_LAST_INTERVAL.save(storage, fp_btc_pk, &(new_interval, new_count))?;

    Ok(())
}

/// Gets the current rate limiting information for a specific finality provider.
///
/// # Arguments
/// * `storage` - Reference to the contract's storage
/// * `fp_btc_pk` - The Bitcoin public key of the finality provider
///
/// # Returns
/// * `Ok(Some((u64, u32)))` containing the current interval and message count for the finality provider
/// * `Ok(None)` if no record exists for this finality provider
/// * `Err(ContractError)` if there's an error accessing storage
pub fn get_rate_limit_info(
    storage: &dyn Storage,
    fp_btc_pk: &[u8],
) -> Result<Option<(u64, u32)>, ContractError> {
    Ok(NUM_MSGS_LAST_INTERVAL.may_load(storage, fp_btc_pk)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::config::{set_config, Config, RateLimitingConfig};
    use crate::testutil::datagen::get_random_fp_pk;
    use cosmwasm_std::testing::{mock_env, MockStorage};
    use cosmwasm_std::Env;
    use rand::{rng, Rng};

    fn setup_test_env_and_storage(
        block_height: u64,
        max_msgs_per_interval: u32,
        block_interval: u64,
    ) -> (Env, MockStorage) {
        let mut env = mock_env();
        env.block.height = block_height;

        let mut storage = MockStorage::new();
        let config = Config {
            bsn_id: "test-bsn".to_string(),
            min_pub_rand: 10,
            rate_limiting: RateLimitingConfig {
                max_msgs_per_interval,
                block_interval,
            },
        };
        set_config(&mut storage, &config).unwrap();

        (env, storage)
    }

    #[test]
    fn test_basic_edge_cases() {
        // Test nonexistent FP returns None
        let (_, storage) = setup_test_env_and_storage(100, 5, 10);
        let fp_btc_pk = get_random_fp_pk();
        let info = get_rate_limit_info(&storage, &fp_btc_pk).unwrap();
        assert!(info.is_none());

        // Test zero height edge case
        let (env, mut storage) = setup_test_env_and_storage(0, 5, 10);
        let fp_btc_pk = get_random_fp_pk();
        assert!(check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk).is_ok());
        let info = get_rate_limit_info(&storage, &fp_btc_pk).unwrap().unwrap();
        assert_eq!(info, (0, 1));
    }

    #[test]
    fn test_randomized_rate_limiting() {
        let mut rng = rng();

        for iteration in 0..100 {
            // Randomize test parameters to cover wide range of scenarios
            let max_msgs = rng.random_range(1..=15);
            let block_interval = rng.random_range(1..=50);
            let starting_height = rng.random_range(0..=500);

            let (mut env, mut storage) =
                setup_test_env_and_storage(starting_height, max_msgs, block_interval);
            let fp_btc_pk = get_random_fp_pk();

            // Test normal operation within limit
            for i in 1..=max_msgs {
                let result = check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk);
                assert!(
                    result.is_ok(),
                    "Iteration {}: Message {} should succeed within limit of {}",
                    iteration,
                    i,
                    max_msgs
                );

                let info = get_rate_limit_info(&storage, &fp_btc_pk).unwrap().unwrap();
                let expected_interval = starting_height / block_interval;
                assert_eq!(info, (expected_interval, i));
            }

            // Test exceeding limit
            let result = check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk);
            assert!(
                result.is_err(),
                "Iteration {}: Message beyond limit should fail",
                iteration
            );
            assert!(matches!(
                result.unwrap_err(),
                ContractError::RateLimitExceeded { .. }
            ));

            // Test interval transition resets count
            let jump_blocks = rng.random_range(1..=3) * block_interval;
            env.block.height += jump_blocks;

            let result = check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk);
            assert!(
                result.is_ok(),
                "Iteration {}: First message in new interval should succeed",
                iteration
            );

            let info = get_rate_limit_info(&storage, &fp_btc_pk).unwrap().unwrap();
            let expected_new_interval = env.block.height / block_interval;
            assert_eq!(info, (expected_new_interval, 1));
        }
    }

    #[test]
    fn test_randomized_multiple_fps_and_block_progression() {
        let mut rng = rng();

        for scenario in 0..25 {
            let max_msgs = rng.random_range(2..=6);
            let block_interval = rng.random_range(10..=100);
            let (mut env, mut storage) = setup_test_env_and_storage(0, max_msgs, block_interval);

            // Generate multiple random finality providers
            let fps: Vec<Vec<u8>> = (0..rng.random_range(5..=20))
                .map(|_| get_random_fp_pk())
                .collect();
            let mut fp_counts = vec![0u32; fps.len()];
            let mut current_interval = 0;

            // Perform operations with block progression
            for step in 0..rng.random_range(100..=300) {
                // Randomly advance block occasionally
                if rng.random_range(0..10) == 0 {
                    let block_jump = rng.random_range(1..=block_interval * 2);
                    env.block.height += block_jump;

                    let new_interval = env.block.height / block_interval;
                    if new_interval != current_interval {
                        current_interval = new_interval;
                        fp_counts.fill(0); // Reset all counts in new interval
                    }
                }

                let fp_index = rng.random_range(0..fps.len());
                let fp = &fps[fp_index];
                let result = check_rate_limit_and_accumulate(&mut storage, &env, fp);

                if fp_counts[fp_index] < max_msgs {
                    // Should succeed
                    assert!(
                        result.is_ok(),
                        "Scenario {}, Step {}: FP {} should succeed with count {}",
                        scenario,
                        step,
                        fp_index,
                        fp_counts[fp_index]
                    );
                    fp_counts[fp_index] += 1;

                    let info = get_rate_limit_info(&storage, fp).unwrap().unwrap();
                    assert_eq!(info, (current_interval, fp_counts[fp_index]));
                } else {
                    // Should fail due to rate limit
                    assert!(
                        result.is_err(),
                        "Scenario {}, Step {}: FP {} should fail with count {}",
                        scenario,
                        step,
                        fp_index,
                        fp_counts[fp_index]
                    );
                    assert!(matches!(
                        result.unwrap_err(),
                        ContractError::RateLimitExceeded { .. }
                    ));
                }
            }
        }
    }

    #[test]
    fn test_randomized_edge_cases_and_boundaries() {
        let mut rng = rng();

        // Test extreme values and edge cases
        for _ in 0..20 {
            let max_msgs = if rng.random_range(0..2) == 0 {
                1
            } else {
                rng.random_range(1..=u32::MAX.min(1000))
            };
            let block_interval = rng.random_range(1..=100);
            let block_height = rng.random_range(0..=1000);

            let (env, mut storage) =
                setup_test_env_and_storage(block_height, max_msgs, block_interval);
            let fp_btc_pk = get_random_fp_pk();

            if max_msgs == 1 {
                // First message should succeed
                assert!(check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk).is_ok());
                // Second message should fail
                let err =
                    check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk).unwrap_err();
                assert!(matches!(err, ContractError::RateLimitExceeded { .. }));
            } else {
                // Should be able to send max_msgs messages
                for _ in 0..max_msgs.min(100) {
                    let result = check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk);
                    assert!(result.is_ok());
                }
            }
        }

        // Test interval calculation edge cases
        let edge_cases = vec![
            (0, 10, 0),
            (9, 10, 0),
            (10, 10, 1),
            (19, 10, 1),
            (20, 10, 2),
            (100, 1, 100),
            (100, 100, 1),
            (1, 1, 1),
            (999, 1000, 0),
        ];

        for (block_height, block_interval, expected_interval) in edge_cases {
            let (env, mut storage) = setup_test_env_and_storage(block_height, 5, block_interval);
            let fp_btc_pk = get_random_fp_pk();

            assert!(check_rate_limit_and_accumulate(&mut storage, &env, &fp_btc_pk).is_ok());

            let info = get_rate_limit_info(&storage, &fp_btc_pk).unwrap().unwrap();
            assert_eq!(
                info.0, expected_interval,
                "Block {} with interval {} should be in interval {}",
                block_height, block_interval, expected_interval
            );
        }
    }
}
