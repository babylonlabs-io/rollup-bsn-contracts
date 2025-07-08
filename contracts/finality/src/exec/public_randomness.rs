use crate::custom_queries::get_current_epoch;
use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::get_config;
use crate::state::public_randomness::{insert_pub_rand_commit, PubRandCommit};
use crate::utils::query_finality_provider;
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{DepsMut, Env, Event, Response};
use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};

const EXPECTED_COMMITMENT_LENGTH_BYTES: usize = 32; // Commitment must be exactly 32 bytes

pub fn handle_public_randomness_commit(
    deps: DepsMut<BabylonQuery>,
    _env: &Env,
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Static validation that can be used by other programs
    let config = get_config(deps.as_ref())?;
    validate_pub_rand_commit_basic(
        fp_btc_pk_hex,
        start_height,
        num_pub_rand,
        commitment,
        signature,
        config.min_pub_rand,
    )?;

    // Ensure the finality provider is registered and not slashed
    ensure_fp_exists_and_not_slashed(deps.as_ref(), fp_btc_pk_hex)?;

    let fp_btc_pk = hex::decode(fp_btc_pk_hex)?;

    // Verify signature over the list
    verify_commitment_signature(
        &fp_btc_pk,
        start_height,
        num_pub_rand,
        commitment,
        signature,
    )?;

    // insert the public randomness commitment into the storage
    // note that `insert_pub_rand_commit` has ensured that
    // - the new commitment does not overlap with the existing ones
    // - the new commitment does not have num_pub_rand = 0
    let current_epoch = get_current_epoch(&deps.as_ref())?;
    insert_pub_rand_commit(
        deps.storage,
        &fp_btc_pk,
        PubRandCommit {
            start_height,
            num_pub_rand,
            babylon_epoch: current_epoch,
            commitment: commitment.to_vec(),
        },
    )?;

    let event = Event::new("public_randomness_commit")
        .add_attribute("fp_pubkey_hex", hex::encode(fp_btc_pk))
        .add_attribute("pr_commit.start_height", start_height.to_string())
        .add_attribute("pr_commit.num_pub_rand", num_pub_rand.to_string());

    Ok(Response::new().add_event(event))
}

/// Static validation function for public randomness commit parameters.
/// This is a "sanity check" function similar to ValidateBasic in Cosmos SDK.
/// It can be used by other offchain programs to validate parameters before submission.
pub fn validate_pub_rand_commit_basic(
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
    min_pub_rand: u64,
) -> Result<(), ContractError> {
    // Check if FP BTC PubKey is empty
    if fp_btc_pk_hex.is_empty() {
        return Err(ContractError::EmptyFpBtcPubKey);
    }

    // Check if commitment is exactly 32 bytes
    if commitment.len() != EXPECTED_COMMITMENT_LENGTH_BYTES {
        return Err(ContractError::InvalidCommitmentLength {
            expected: EXPECTED_COMMITMENT_LENGTH_BYTES,
            actual: commitment.len(),
        });
    }

    // Check for overflow when doing (StartHeight + NumPubRand)
    // To avoid public randomness reset
    let end_height = start_height.saturating_add(num_pub_rand);
    if start_height >= end_height {
        return Err(ContractError::OverflowInBlockHeight {
            start_height,
            end_height,
        });
    }

    // Check if signature is empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }

    // Validate minimum public randomness requirement
    if num_pub_rand < min_pub_rand {
        return Err(ContractError::TooFewPubRand {
            given: num_pub_rand,
            required: min_pub_rand,
        });
    }

    Ok(())
}

fn verify_commitment_signature(
    fp_btc_pk: &[u8],
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // get BTC public key for verification
    let btc_pk = VerifyingKey::from_bytes(fp_btc_pk)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signature
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }
    let schnorr_sig =
        Signature::try_from(signature).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get signed message
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(&start_height.to_be_bytes());
    msg.extend_from_slice(&num_pub_rand.to_be_bytes());
    msg.extend_from_slice(commitment);

    // Verify the signature
    btc_pk
        .verify(&msg, &schnorr_sig)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
}

fn ensure_fp_exists_and_not_slashed(
    deps: cosmwasm_std::Deps<BabylonQuery>,
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    // Ensure the finality provider is registered and not slashed
    let config = get_config(deps)?;
    let fp_info = query_finality_provider(deps, config.consumer_id, fp_btc_pk_hex.to_string())?;
    if fp_info.slashed_babylon_height > 0 {
        return Err(ContractError::SlashedFinalityProvider(
            fp_btc_pk_hex.to_string(),
            fp_info.slashed_babylon_height,
            fp_info.slashed_btc_height,
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn verify_commitment_signature_works() {
        use babylon_test_utils::get_public_randomness_commitment;
        
        // Define test values
        let (fp_btc_pk_hex, pr_commit, sig) = get_public_randomness_commitment();
        let fp_btc_pk = hex::decode(&fp_btc_pk_hex).unwrap();

        // Verify commitment signature
        let res = verify_commitment_signature(
            &fp_btc_pk,
            pr_commit.start_height,
            pr_commit.num_pub_rand,
            &pr_commit.commitment,
            &sig,
        );
        assert!(res.is_ok());
    }

    mod validation_tests {
        use super::*;
        use crate::contract::tests::mock_deps_babylon;
        use crate::state::config::{Config, CONFIG};
        use cosmwasm_std::testing::mock_env;

        #[test]
        fn test_empty_fp_btc_pk_fails() {
            let mut deps = mock_deps_babylon();

            // Configure the contract with min_pub_rand
            let config = Config {
                consumer_id: "test".to_string(),
                min_pub_rand: 100,
            };
            CONFIG.save(deps.as_mut().storage, &config).unwrap();

            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "", // Empty FP BTC pubkey should fail
                100,
                100,
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES],
                &[1u8; 64],
            );

            assert_eq!(result.unwrap_err(), ContractError::EmptyFpBtcPubKey);
        }

        #[test]
        fn test_invalid_commitment_length_fails() {
            let mut deps = mock_deps_babylon();

            // Configure the contract with min_pub_rand
            let config = Config {
                consumer_id: "test".to_string(),
                min_pub_rand: 100,
            };
            CONFIG.save(deps.as_mut().storage, &config).unwrap();

            // Test commitment too short
            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "valid_fp_key",
                100,
                100,
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES - 1], // Too short
                &[1u8; 64],
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::InvalidCommitmentLength {
                    expected: EXPECTED_COMMITMENT_LENGTH_BYTES,
                    actual: EXPECTED_COMMITMENT_LENGTH_BYTES - 1
                }
            );

            // Test commitment too long
            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "valid_fp_key",
                100,
                100,
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES + 1], // Too long
                &[1u8; 64],
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::InvalidCommitmentLength {
                    expected: EXPECTED_COMMITMENT_LENGTH_BYTES,
                    actual: EXPECTED_COMMITMENT_LENGTH_BYTES + 1
                }
            );
        }

        #[test]
        fn test_empty_signature_fails() {
            let mut deps = mock_deps_babylon();

            // Configure the contract with min_pub_rand
            let config = Config {
                consumer_id: "test".to_string(),
                min_pub_rand: 100,
            };
            CONFIG.save(deps.as_mut().storage, &config).unwrap();

            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "valid_fp_key",
                100,
                100,
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES],
                &[], // Empty signature should fail
            );

            assert_eq!(result.unwrap_err(), ContractError::EmptySignature);
        }

        #[test]
        fn test_overflow_protection_fails() {
            let mut deps = mock_deps_babylon();

            // Configure the contract with min_pub_rand
            let config = Config {
                consumer_id: "test".to_string(),
                min_pub_rand: 100,
            };
            CONFIG.save(deps.as_mut().storage, &config).unwrap();

            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "valid_fp_key",
                u64::MAX, // This will cause overflow when added to num_pub_rand
                1,
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES],
                &[1u8; 64],
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::OverflowInBlockHeight {
                    start_height: u64::MAX,
                    end_height: u64::MAX // saturating_add results in MAX
                }
            );
        }

        #[test]
        fn test_minimum_pub_rand_validation_fails() {
            let mut deps = mock_deps_babylon();

            // Configure the contract with min_pub_rand = 100
            let config = Config {
                consumer_id: "test".to_string(),
                min_pub_rand: 100,
            };
            CONFIG.save(deps.as_mut().storage, &config).unwrap();

            let result = handle_public_randomness_commit(
                deps.as_mut(),
                &mock_env(),
                "valid_fp_key",
                100,
                50, // Less than minimum of 100 should fail
                &[0u8; EXPECTED_COMMITMENT_LENGTH_BYTES],
                &[1u8; 64],
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::TooFewPubRand {
                    given: 50,
                    required: 100
                }
            );
        }

        #[test]
        fn test_validation_constants_match_go() {
            // Verify our constants match the expected values
            assert_eq!(
                EXPECTED_COMMITMENT_LENGTH_BYTES, 32,
                "EXPECTED_COMMITMENT_LENGTH_BYTES should match expected value"
            );
        }
    }
} 