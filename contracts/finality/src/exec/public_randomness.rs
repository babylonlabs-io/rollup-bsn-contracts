use crate::custom_queries::get_current_epoch;
use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::{ensure_fp_in_allowlist, get_config};
use crate::state::public_randomness::{insert_pub_rand_commit, PubRandCommit};
use crate::utils::get_fp_rand_commit_context_v0;
use crate::utils::query_finality_provider;
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{DepsMut, Env, Event, Response};
use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};

const COMMITMENT_LENGTH_BYTES: usize = 32; // Commitment must be exactly 32 bytes
const BIP340_SIGNATURE_LENGTH_BYTES: usize = 64; // BIP340 signatures must be exactly 64 bytes

pub fn handle_public_randomness_commit(
    deps: DepsMut<BabylonQuery>,
    env: &Env,
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check if FP BTC PubKey is empty
    if fp_btc_pk_hex.is_empty() {
        return Err(ContractError::EmptyFpBtcPubKey);
    }

    // Check if signature is empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }

    // Check if signature is exactly 64 bytes (BIP340 requirement)
    if signature.len() != BIP340_SIGNATURE_LENGTH_BYTES {
        return Err(ContractError::InvalidSignatureLength {
            expected: BIP340_SIGNATURE_LENGTH_BYTES,
            actual: signature.len(),
        });
    }

    let config = get_config(deps.as_ref())?;

    // Validate the commitment parameters
    validate_pub_rand_commit(start_height, num_pub_rand, commitment, config.min_pub_rand)?;

    // Check if the finality provider is in the allowlist
    ensure_fp_in_allowlist(deps.storage, fp_btc_pk_hex)?;

    // Ensure the finality provider is registered and not slashed
    ensure_fp_exists_and_not_slashed(deps.as_ref(), fp_btc_pk_hex)?;

    let fp_btc_pk = hex::decode(fp_btc_pk_hex)?;
    let context = get_fp_rand_commit_context_v0(env)?;
    // Verify signature over the list
    verify_commitment_signature(
        &fp_btc_pk,
        start_height,
        num_pub_rand,
        commitment,
        &context,
        signature,
    )?;

    // insert the public randomness commitment into the storage
    // note that `insert_pub_rand_commit` has ensured that
    // - the new commitment does not overlap with the existing ones
    // - the new commitment >= min_pub_rand
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

pub fn validate_pub_rand_commit(
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    min_pub_rand: u64,
) -> Result<(), ContractError> {
    // Check if commitment is exactly 32 bytes
    if commitment.len() != COMMITMENT_LENGTH_BYTES {
        return Err(ContractError::InvalidCommitmentLength {
            expected: COMMITMENT_LENGTH_BYTES,
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

    // Validate minimum public randomness requirement
    if num_pub_rand < min_pub_rand {
        return Err(ContractError::TooFewPubRand {
            given: num_pub_rand,
            required: min_pub_rand,
        });
    }

    Ok(())
}

// Copied from contracts/btc-staking/src/finality.rs
fn verify_commitment_signature(
    fp_btc_pk: &[u8],
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    context: &str,
    signature: &[u8],
) -> Result<(), ContractError> {
    // get BTC public key for verification
    let btc_pk = VerifyingKey::from_bytes(fp_btc_pk)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    let schnorr_sig =
        Signature::try_from(signature).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get message to be signed
    // (signing_context || start_height || num_pub_rand || commitment)
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(context.as_bytes());
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
    let fp_info = query_finality_provider(deps, fp_btc_pk_hex.to_string())?;
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
    use crate::contract::tests::mock_deps_babylon;
    use crate::state::config::{Config, CONFIG};
    use babylon_test_utils::get_public_randomness_commitment;
    use cosmwasm_std::testing::mock_env;

    #[test]
    fn verify_commitment_signature_works() {
        // Define test values
        let (fp_btc_pk_hex, pr_commit, sig) = get_public_randomness_commitment();
        let fp_btc_pk = hex::decode(&fp_btc_pk_hex).unwrap();

        // Verify commitment signature
        // TODO: test with non-empty signing context
        // this needs mock data from babylon_test_utils
        // https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/66
        let signing_context = "";
        let res = verify_commitment_signature(
            &fp_btc_pk,
            pr_commit.start_height,
            pr_commit.num_pub_rand,
            &pr_commit.commitment,
            signing_context,
            &sig,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_empty_fp_btc_pk_fails() {
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: get_random_u64(),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        // Generate random 64-byte signature
        let mut rng = rng();
        let random_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES)
            .map(|_| rng.random())
            .collect();

        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            "", // Empty FP BTC pubkey should fail
            get_random_u64(),
            get_random_u64(),
            &get_random_block_hash(),
            &random_signature,
        );

        assert_eq!(result.unwrap_err(), ContractError::EmptyFpBtcPubKey);
    }

    #[test]
    fn test_invalid_commitment_length_fails() {
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: get_random_u64(),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let start_height = get_random_u64();
        let num_pub_rand = get_random_u64();

        // Generate random 64-byte signature
        let mut rng = rng();
        let random_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES)
            .map(|_| rng.random())
            .collect();

        // Test commitment too short
        let short_commitment: Vec<u8> = (0..COMMITMENT_LENGTH_BYTES - 1)
            .map(|_| rng.random())
            .collect();
        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &fp_btc_pk_hex,
            start_height,
            num_pub_rand,
            &short_commitment, // Too short
            &random_signature,
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::InvalidCommitmentLength {
                expected: COMMITMENT_LENGTH_BYTES,
                actual: COMMITMENT_LENGTH_BYTES - 1
            }
        );

        // Test commitment too long
        let long_commitment: Vec<u8> = (0..COMMITMENT_LENGTH_BYTES + 1)
            .map(|_| rng.random())
            .collect();
        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &fp_btc_pk_hex,
            start_height,
            num_pub_rand,
            &long_commitment, // Too long
            &random_signature,
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::InvalidCommitmentLength {
                expected: COMMITMENT_LENGTH_BYTES,
                actual: COMMITMENT_LENGTH_BYTES + 1
            }
        );
    }

    #[test]
    fn test_empty_signature_fails() {
        use crate::testutil::datagen::*;

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: get_random_u64(),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &get_random_fp_pk_hex(),
            get_random_u64(),
            get_random_u64(),
            &get_random_block_hash(),
            &[], // Empty signature should fail
        );

        assert_eq!(result.unwrap_err(), ContractError::EmptySignature);
    }

    #[test]
    fn test_invalid_signature_length_fails() {
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: get_random_u64(),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let start_height = get_random_u64();
        let num_pub_rand = get_random_u64();
        let commitment = get_random_block_hash();

        let mut rng = rng();

        // Test signature too short
        let short_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES - 1)
            .map(|_| rng.random())
            .collect();
        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &fp_btc_pk_hex,
            start_height,
            num_pub_rand,
            &commitment,
            &short_signature, // Too short
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::InvalidSignatureLength {
                expected: BIP340_SIGNATURE_LENGTH_BYTES,
                actual: BIP340_SIGNATURE_LENGTH_BYTES - 1
            }
        );

        // Test signature too long
        let long_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES + 1)
            .map(|_| rng.random())
            .collect();
        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &fp_btc_pk_hex,
            start_height,
            num_pub_rand,
            &commitment,
            &long_signature, // Too long
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::InvalidSignatureLength {
                expected: BIP340_SIGNATURE_LENGTH_BYTES,
                actual: BIP340_SIGNATURE_LENGTH_BYTES + 1
            }
        );
    }

    #[test]
    fn test_overflow_protection_fails() {
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: get_random_u64(),
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        // Generate random 64-byte signature
        let mut rng = rng();
        let random_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES)
            .map(|_| rng.random())
            .collect();

        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &get_random_fp_pk_hex(),
            u64::MAX, // This will cause overflow when added to num_pub_rand
            1,
            &get_random_block_hash(),
            &random_signature,
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
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with random min_pub_rand
        let min_pub_rand = get_random_u64().max(10); // Ensure it's at least 10
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand,
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        // Generate random 64-byte signature
        let mut rng = rng();
        let random_signature: Vec<u8> = (0..BIP340_SIGNATURE_LENGTH_BYTES)
            .map(|_| rng.random())
            .collect();

        // Use a value less than min_pub_rand
        let too_few_pub_rand = min_pub_rand.saturating_sub(1);

        let result = handle_public_randomness_commit(
            deps.as_mut(),
            &mock_env(),
            &get_random_fp_pk_hex(),
            get_random_u64(),
            too_few_pub_rand, // Less than minimum should fail
            &get_random_block_hash(),
            &random_signature,
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::TooFewPubRand {
                given: too_few_pub_rand,
                required: min_pub_rand
            }
        );
    }
}
