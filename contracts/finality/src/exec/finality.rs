use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::get_config;
use crate::state::finality::{
    insert_finality_sig_and_signatory, list_finality_signatures, FinalitySigInfo,
};
use crate::state::public_randomness::{
    get_timestamped_pub_rand_commit_for_height, insert_pub_rand_value, PubRandCommit,
};
use crate::utils::{get_fp_fin_vote_context_v0, query_finality_provider};
use babylon_bindings::BabylonQuery;
use babylon_merkle::Proof;
use cosmwasm_std::{Deps, DepsMut, Env, Event, Response};
use k256::sha2::{Digest, Sha256};

#[allow(clippy::too_many_arguments)]
pub fn handle_finality_signature(
    deps: DepsMut<BabylonQuery>,
    env: &Env,
    fp_btc_pk_hex: &str,
    l1_block_number: Option<u64>,
    l1_block_hash_hex: Option<String>,
    height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    block_hash: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Load config first
    let config = get_config(deps.as_ref())?;

    // Ensure system is activated
    if height < config.bsn_activation_height {
        return Err(ContractError::BeforeSystemActivation(
            height,
            config.bsn_activation_height,
        ));
    }

    // Ensure finality signature interval is respected
    if (height - config.bsn_activation_height) % config.finality_signature_interval != 0 {
        return Err(ContractError::FinalitySignatureRateLimitExceeded(
            height,
            config.finality_signature_interval,
        ));
    }

    // Now proceed with other validations only if rate limiting passes
    // Ensure the finality provider exists and is not slashed
    ensure_fp_exists_and_not_slashed(deps.as_ref(), fp_btc_pk_hex)?;

    let fp_btc_pk = hex::decode(fp_btc_pk_hex)?;

    // Load any existing finality signature by the finality provider at the same height
    let existing_finality_sigs = list_finality_signatures(deps.storage, height, &fp_btc_pk)?;

    // check if the finality signature submission is the same as an existing one
    if let Some(existing_sigs) = &existing_finality_sigs {
        let new_sig_info = FinalitySigInfo {
            finality_sig: signature.to_vec(),
            block_hash: block_hash.to_vec(),
        };

        if existing_sigs.contains(&new_sig_info) {
            deps.api.debug(&format!("Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return error
            return Err(ContractError::DuplicatedFinalitySig(
                fp_btc_pk_hex.to_string(),
                height,
            ));
        }
    }

    // Next, we are verifying the finality signature message
    // Find the public randomness commitment for this height from this finality provider
    let pr_commit = get_timestamped_pub_rand_commit_for_height(&deps.as_ref(), &fp_btc_pk, height)?;

    // Verify the finality signature message
    let context = get_fp_fin_vote_context_v0(env)?;
    verify_finality_signature(
        &fp_btc_pk, height, pub_rand, proof, &pr_commit, block_hash, &context, signature,
    )?;

    // Save the finality signature and signatory in an atomic operation
    // to record the fact that this finality provider has signed the (height, block_hash) pair
    // NOTE: The signature will be inserted even if this is an equivocation
    insert_finality_sig_and_signatory(deps.storage, &fp_btc_pk, height, block_hash, signature)?;

    // Build the response
    let mut res: Response<BabylonMsg> = Response::new();

    // Add event to the response
    let mut event = Event::new("submit_finality_signature")
        .add_attribute("fp_pubkey_hex", fp_btc_pk_hex)
        .add_attribute("block_height", height.to_string())
        .add_attribute("block_hash", hex::encode(block_hash));
    if let Some(l1_block_number) = l1_block_number {
        event = event.add_attribute("l1_block_number", l1_block_number.to_string());
    }
    if let Some(l1_block_hash_hex) = l1_block_hash_hex {
        event = event.add_attribute("l1_block_hash_hex", l1_block_hash_hex);
    }
    res = res.add_event(event);

    // Check for equivocation - if there are existing signatures, this is equivocation
    if let Some(existing_sigs) = existing_finality_sigs {
        // Take the first existing signature for equivocation evidence
        let existing_sig = existing_sigs.iter().next().unwrap();

        // The finality provider has voted for a different signature at the same height!
        // send equivocation evidence to Babylon Genesis for slashing
        let msg = get_msg_equivocation_evidence(
            env,
            &fp_btc_pk,
            height,
            pub_rand,
            &existing_sig.block_hash,
            &existing_sig.finality_sig,
            block_hash,
            signature,
            &context,
        )?;
        res = res.add_message(msg);
    } else {
        // This is the first time seeing this finality provider submit finality
        // signature at this height

        // store public randomness
        insert_pub_rand_value(deps.storage, &fp_btc_pk, height, pub_rand)?;
    }

    Ok(res)
}

/// Verifies the finality signature message w.r.t. the public randomness commitment:
/// - Public randomness inclusion proof.
/// - Finality signature
#[allow(clippy::too_many_arguments)]
fn verify_finality_signature(
    fp_btc_pk: &[u8],
    block_height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    pr_commit: &PubRandCommit,
    block_hash: &[u8],
    signing_context: &str,
    signature: &[u8],
) -> Result<(), ContractError> {
    let proof_height = pr_commit.start_height + proof.index;
    if block_height != proof_height {
        return Err(ContractError::InvalidFinalitySigHeight(
            proof_height,
            block_height,
        ));
    }
    // Verify the total amount of randomness is the same as in the commitment
    if proof.total != pr_commit.num_pub_rand {
        return Err(ContractError::InvalidFinalitySigAmount(
            proof.total,
            pr_commit.num_pub_rand,
        ));
    }
    // Verify the proof of inclusion for this public randomness
    proof.validate_basic()?;
    proof.verify(&pr_commit.commitment, pub_rand)?;

    // Public randomness is good, verify finality signature
    let pubkey = eots::PublicKey::from_bytes(fp_btc_pk)?;

    // get message to be signed
    // (signing_context || block_height || block_hash)
    let mut msg = vec![];
    msg.extend_from_slice(signing_context.as_bytes());
    msg.extend_from_slice(&block_height.to_be_bytes());
    msg.extend_from_slice(block_hash);
    let msg_hash = Sha256::digest(msg);

    if !pubkey.verify(pub_rand, &msg_hash, signature)? {
        return Err(ContractError::FailedSignatureVerification("EOTS".into()));
    }
    Ok(())
}

fn ensure_fp_exists_and_not_slashed(
    deps: Deps<BabylonQuery>,
    fp_pubkey_hex: &str,
) -> Result<(), ContractError> {
    let config = get_config(deps)?;
    let fp = query_finality_provider(deps, fp_pubkey_hex.to_string());
    match fp {
        // the finality provider is found but is associated with other BSNs
        Ok(value) if value.bsn_id != config.bsn_id => Err(ContractError::NotFoundFinalityProvider(
            config.bsn_id,
            fp_pubkey_hex.to_string(),
        )),
        // the finality provider is found but is slashed
        Ok(value) if value.is_slashed() => Err(ContractError::SlashedFinalityProvider(
            fp_pubkey_hex.to_string(),
            value.slashed_babylon_height,
            value.slashed_btc_height,
        )),
        // other errors
        Err(_e) => Err(ContractError::NotFoundFinalityProvider(
            config.bsn_id,
            fp_pubkey_hex.to_string(),
        )),
        // the finality provider is found, is associated with the correct BSN, and is not slashed
        Ok(_) => Ok(()),
    }
}

/// `get_msg_equivocation_evidence` returns the message for an equivocation evidence.
/// The message will be sent to Babylon for slashing
#[allow(clippy::too_many_arguments)]
fn get_msg_equivocation_evidence(
    env: &Env,
    fp_btc_pk: &[u8],
    block_height: u64,
    pub_rand: &[u8],
    canonical_app_hash: &[u8],
    canonical_finality_sig: &[u8],
    fork_app_hash: &[u8],
    fork_finality_sig: &[u8],
    signing_context: &str,
) -> Result<BabylonMsg, ContractError> {
    let fp_btc_pk_hex = hex::encode(fp_btc_pk);
    let pub_rand_hex = hex::encode(pub_rand);
    let canonical_app_hash_hex = hex::encode(canonical_app_hash);
    let fork_app_hash_hex = hex::encode(fork_app_hash);
    let canonical_finality_sig_hex = hex::encode(canonical_finality_sig);
    let fork_finality_sig_hex = hex::encode(fork_finality_sig);

    let msg = BabylonMsg::MsgEquivocationEvidence {
        signer: env.contract.address.to_string(),
        fp_btc_pk_hex,
        block_height,
        pub_rand_hex,
        canonical_app_hash_hex,
        fork_app_hash_hex,
        canonical_finality_sig_hex,
        fork_finality_sig_hex,
        signing_context: signing_context.to_string(),
    };

    Ok(msg)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use babylon_test_utils::{
        get_add_finality_sig, get_add_finality_sig_2, get_pub_rand_value,
        get_public_randomness_commitment,
    };
    use cosmwasm_std::testing::mock_env;

    #[test]
    fn verify_finality_signature_works() {
        // Read public randomness commitment test data
        let (pk_hex, pr_commit, _) = get_public_randomness_commitment();
        let pub_rand_value = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let current_epoch = 1;

        // Convert the PubRandCommit in the type defined in this contract
        let pr_commit = PubRandCommit {
            start_height: pr_commit.start_height,
            num_pub_rand: pr_commit.num_pub_rand,
            babylon_epoch: current_epoch,
            commitment: pr_commit.commitment,
        };

        // Verify finality signature
        // TODO: test with non-empty signing context
        // This needs mock data from babylon_test_utils
        // https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/66
        let context = "";
        let res = verify_finality_signature(
            &hex::decode(&pk_hex).unwrap(),
            pr_commit.start_height + proof.index.unsigned_abs(),
            &pub_rand_value,
            // we need to add a typecast below because the provided proof is of type
            // tendermint_proto::crypto::Proof, whereas the fn expects babylon_merkle::proof
            &proof.into(),
            &pr_commit,
            &add_finality_signature.block_app_hash,
            context,
            &add_finality_signature.finality_sig,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn verify_slashing_works() {
        // Read test data
        let (pk_hex, pr_commit, _) = get_public_randomness_commitment();
        let fp_btc_pk = hex::decode(&pk_hex).unwrap();
        let pub_rand_value = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let add_finality_signature_2 = get_add_finality_sig_2();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pr_commit.start_height;
        let block_height = initial_height + proof.index.unsigned_abs();

        let env = mock_env();

        // Test slash_finality_provider
        let msg = get_msg_equivocation_evidence(
            &env,
            &fp_btc_pk,
            block_height,
            &pub_rand_value,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
            &add_finality_signature_2.block_app_hash,
            &add_finality_signature_2.finality_sig,
            "",
        )
        .unwrap();

        // TODO: do equivocation here through handle_finality_signature
        // need https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/54

        // Verify the BabylonMsg is correctly constructed
        match msg {
            BabylonMsg::MsgEquivocationEvidence {
                signer,
                fp_btc_pk_hex,
                block_height: msg_height,
                pub_rand_hex,
                canonical_app_hash_hex,
                fork_app_hash_hex,
                canonical_finality_sig_hex,
                fork_finality_sig_hex,
                signing_context,
            } => {
                assert_eq!(signer, env.contract.address.to_string());
                assert_eq!(fp_btc_pk_hex, hex::encode(&fp_btc_pk));
                assert_eq!(msg_height, block_height);
                assert_eq!(pub_rand_hex, hex::encode(&pub_rand_value));
                assert_eq!(
                    canonical_app_hash_hex,
                    hex::encode(&add_finality_signature.block_app_hash)
                );
                assert_eq!(
                    fork_app_hash_hex,
                    hex::encode(&add_finality_signature_2.block_app_hash)
                );
                assert_eq!(
                    canonical_finality_sig_hex,
                    hex::encode(&add_finality_signature.finality_sig)
                );
                assert_eq!(
                    fork_finality_sig_hex,
                    hex::encode(&add_finality_signature_2.finality_sig)
                );
                assert_eq!(signing_context, "");
            }
        }
    }

    #[test]
    fn test_finality_signature_system_activation_check() {
        use crate::contract::tests::mock_deps_babylon;
        use crate::state::config::{Config, CONFIG};
        use crate::testutil::datagen::*;

        let mut deps = mock_deps_babylon();

        // Configure the contract with activation height of 1000
        let activation_height = 1000;
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: 1,
            bsn_activation_height: activation_height,
            finality_signature_interval: 5,
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap().into();

        // FAIL CASE: Try to submit finality signature before activation
        let before_activation_height = activation_height - 1;
        let result = handle_finality_signature(
            deps.as_mut(),
            &mock_env(),
            &get_random_fp_pk_hex(),
            None,
            None,
            before_activation_height, // Before activation should fail
            &add_finality_signature.pub_rand,
            &proof,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
        );

        assert_eq!(
            result.unwrap_err(),
            ContractError::BeforeSystemActivation(before_activation_height, activation_height),
            "Should fail when height < activation_height"
        );

        // PASS CASE: Try to submit finality signature at activation height (should pass system activation)
        let result = handle_finality_signature(
            deps.as_mut(),
            &mock_env(),
            &get_random_fp_pk_hex(),
            None,
            None,
            activation_height, // At activation height should pass
            &add_finality_signature.pub_rand,
            &proof,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
        );

        // Should fail at a later stage (FP not found), not at system activation
        assert_ne!(
            result.unwrap_err(),
            ContractError::BeforeSystemActivation(activation_height, activation_height),
            "Should pass system activation check when height >= activation_height"
        );
    }

        #[test]
    fn test_finality_signature_interval_validation() {
        use crate::contract::tests::mock_deps_babylon;
        use crate::state::config::{Config, CONFIG};
        use crate::testutil::datagen::*;
        use rand::{rng, Rng};

        let mut deps = mock_deps_babylon();

        // Configure the contract with activation height of 1000 and interval of 5
        let activation_height = 1000;
        let interval = 5;
        let config = Config {
            bsn_id: format!("test-{}", get_random_u64()),
            min_pub_rand: 1,
            bsn_activation_height: activation_height,
            finality_signature_interval: interval,
        };
        CONFIG.save(deps.as_mut().storage, &config).unwrap();

        // Generate test data
        let mut rng = rng();
        let random_signature: Vec<u8> = (0..64).map(|_| rng.random()).collect();
        let random_pub_rand: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        let random_block_hash: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap().into();

        // TEST FAIL CASE: Invalid interval heights should fail with rate limit error
        let invalid_heights = vec![
            activation_height + 1, // 1001: (1001-1000) % 5 = 1 ≠ 0
            activation_height + 2, // 1002: (1002-1000) % 5 = 2 ≠ 0
            activation_height + 3, // 1003: (1003-1000) % 5 = 3 ≠ 0
            activation_height + 4, // 1004: (1004-1000) % 5 = 4 ≠ 0
            activation_height + 6, // 1006: (1006-1000) % 5 = 1 ≠ 0
        ];

        for invalid_height in invalid_heights {
            let result = handle_finality_signature(
                deps.as_mut(),
                &mock_env(),
                &get_random_fp_pk_hex(),
                None,
                None,
                invalid_height,
                &random_pub_rand,
                &proof,
                &random_block_hash,
                &random_signature,
            );

            assert_eq!(
                result.unwrap_err(),
                ContractError::FinalitySignatureRateLimitExceeded(invalid_height, interval),
                "Height {} should fail interval check", invalid_height
            );
        }

        // TEST PASS CASE: Valid interval heights should pass rate limiting
        let valid_heights = vec![
            activation_height,      // 1000: (1000-1000) % 5 = 0 ✅
            activation_height + 5,  // 1005: (1005-1000) % 5 = 0 ✅
            activation_height + 10, // 1010: (1010-1000) % 5 = 0 ✅
            activation_height + 15, // 1015: (1015-1000) % 5 = 0 ✅
        ];

        for valid_height in valid_heights {
            let result = handle_finality_signature(
                deps.as_mut(),
                &mock_env(),
                &get_random_fp_pk_hex(),
                None,
                None,
                valid_height,
                &random_pub_rand,
                &proof,
                &random_block_hash,
                &random_signature,
            );

            // Should pass rate limiting but fail at later validation stage (FP not found)
            let error = result.unwrap_err();
            assert_ne!(
                error,
                ContractError::BeforeSystemActivation(valid_height, activation_height),
                "Height {} should pass system activation check", valid_height
            );
            assert_ne!(
                error,
                ContractError::FinalitySignatureRateLimitExceeded(valid_height, interval),
                "Height {} should pass interval check", valid_height
            );
        }
    }
}
