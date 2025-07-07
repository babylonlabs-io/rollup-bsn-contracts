use crate::custom_queries::get_current_epoch;
use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::CONFIG;
use crate::state::finality::{
    insert_finality_sig_and_signatory, FinalitySigInfo, FINALITY_SIGNATURES,
};
use crate::state::public_randomness::{
    get_timestamped_pub_rand_commit_for_height, insert_pub_rand_commit, insert_pub_rand_value,
    PubRandCommit,
};
use crate::utils::query_finality_provider;
use babylon_bindings::BabylonQuery;
use babylon_merkle::Proof;
use cosmwasm_std::{Deps, DepsMut, Env, Event, MessageInfo, Response};
use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};

pub fn handle_public_randomness_commit(
    deps: DepsMut<BabylonQuery>,
    _env: &Env,
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
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
            babylon_genesis_epoch: current_epoch,
            commitment: commitment.to_vec(),
        },
    )?;

    let event = Event::new("public_randomness_commit")
        .add_attribute("fp_pubkey_hex", hex::encode(fp_btc_pk))
        .add_attribute("pr_commit.start_height", start_height.to_string())
        .add_attribute("pr_commit.num_pub_rand", num_pub_rand.to_string());

    Ok(Response::new().add_event(event))
}

// Copied from contracts/btc-staking/src/finality.rs
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

#[allow(clippy::too_many_arguments)]
pub fn handle_finality_signature(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    fp_btc_pk_hex: &str,
    l1_block_number: Option<u64>,
    l1_block_hash_hex: Option<String>,
    height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    block_hash: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the finality provider exists and is not slashed
    ensure_fp_exists_and_not_slashed(deps.as_ref(), fp_btc_pk_hex)?;

    let fp_btc_pk = hex::decode(fp_btc_pk_hex)?;

    // Load any type of existing finality signature by the finality provider at the same height
    let existing_finality_sig: Option<FinalitySigInfo> =
        FINALITY_SIGNATURES.may_load(deps.storage, (height, &fp_btc_pk))?;

    // check if the finality signature submission is the same as the existing one
    if let Some(existing_sig) = &existing_finality_sig {
        if existing_sig.finality_sig == signature {
            deps.api.debug(&format!("Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return success to the provider
            return Ok(Response::new());
        }
    }

    // Next, we are verifying the finality signature message
    // Find the public randomness commitment for this height from this finality provider
    let pr_commit = get_timestamped_pub_rand_commit_for_height(&deps.as_ref(), &fp_btc_pk, height)?;

    // Verify the finality signature message
    verify_finality_signature(
        &fp_btc_pk, height, pub_rand, proof, &pr_commit, block_hash, signature,
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

    if let Some(existing_finality_sig) = existing_finality_sig {
        // The finality provider has voted for a different block at the same height!
        // send equivocation evidence to Babylon Genesis for slashing
        let msg = get_msg_equivocation_evidence(
            &info,
            &fp_btc_pk,
            height,
            pub_rand,
            &existing_finality_sig.block_hash,
            &existing_finality_sig.finality_sig,
            block_hash,
            signature,
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
fn verify_finality_signature(
    fp_btc_pk: &[u8],
    block_height: u64,
    pub_rand: &[u8],
    proof: &Proof,
    pr_commit: &PubRandCommit,
    app_hash: &[u8],
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
    let msg = msg_to_sign(block_height, app_hash);
    let msg_hash = Sha256::digest(msg);

    if !pubkey.verify(pub_rand, &msg_hash, signature)? {
        return Err(ContractError::FailedSignatureVerification("EOTS".into()));
    }
    Ok(())
}

/// `msg_to_sign` returns the message for an EOTS signature.
///
/// The EOTS signature on a block will be (block_height || block_app_hash)
fn msg_to_sign(height: u64, block_app_hash: &[u8]) -> Vec<u8> {
    let mut msg: Vec<u8> = height.to_be_bytes().to_vec();
    msg.extend_from_slice(block_app_hash);
    msg
}

fn ensure_fp_exists_and_not_slashed(
    deps: Deps<BabylonQuery>,
    fp_pubkey_hex: &str,
) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let fp = query_finality_provider(deps, config.consumer_id.clone(), fp_pubkey_hex.to_string());
    match fp {
        Ok(value) if value.is_slashed() => Err(ContractError::SlashedFinalityProvider(
            fp_pubkey_hex.to_string(),
            value.slashed_babylon_height,
            value.slashed_btc_height,
        )),
        Ok(_) => Ok(()),
        Err(_e) => Err(ContractError::NotFoundFinalityProvider(
            config.consumer_id,
            fp_pubkey_hex.to_string(),
        )),
    }
}

/// `get_msg_equivocation_evidence` returns the message for an equivocation evidence.
/// The message will be sent to Babylon for slashing
fn get_msg_equivocation_evidence(
    info: &MessageInfo,
    fp_btc_pk: &[u8],
    block_height: u64,
    pub_rand: &[u8],
    canonical_app_hash: &[u8],
    canonical_finality_sig: &[u8],
    fork_app_hash: &[u8],
    fork_finality_sig: &[u8],
) -> Result<BabylonMsg, ContractError> {
    let fp_btc_pk_hex = hex::encode(fp_btc_pk);
    let pub_rand_hex = hex::encode(pub_rand);
    let canonical_app_hash_hex = hex::encode(canonical_app_hash);
    let fork_app_hash_hex = hex::encode(fork_app_hash);
    let canonical_finality_sig_hex = hex::encode(canonical_finality_sig);
    let fork_finality_sig_hex = hex::encode(fork_finality_sig);

    let msg = BabylonMsg::MsgEquivocationEvidence {
        signer: info.sender.to_string(),
        fp_btc_pk_hex,
        block_height,
        pub_rand_hex,
        canonical_app_hash_hex,
        fork_app_hash_hex,
        canonical_finality_sig_hex,
        fork_finality_sig_hex,
        signing_context: "".to_string(), // TODO: support signing context
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
    use cosmwasm_std::{testing::message_info, Addr};

    #[test]
    fn verify_commitment_signature_works() {
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

    #[test]
    fn verify_finality_signature_works() {
        // Read public randomness commitment test data
        let (pk_hex, pr_commit, _) = get_public_randomness_commitment();
        let pub_rand_one = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let proof = add_finality_signature.proof.unwrap();

        let current_epoch = 1;

        // Convert the PubRandCommit in the type defined in this contract
        let pr_commit = PubRandCommit {
            start_height: pr_commit.start_height,
            num_pub_rand: pr_commit.num_pub_rand,
            babylon_genesis_epoch: current_epoch,
            commitment: pr_commit.commitment,
        };

        // Verify finality signature
        assert!(proof.index >= 0, "Proof index should be non-negative");
        let res = verify_finality_signature(
            &hex::decode(&pk_hex).unwrap(),
            pr_commit.start_height + proof.index.unsigned_abs(),
            &pub_rand_one,
            // we need to add a typecast below because the provided proof is of type
            // tendermint_proto::crypto::Proof, whereas the fn expects babylon_merkle::proof
            &proof.into(),
            &pr_commit,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn verify_slashing_works() {
        // Read test data
        let (pk_hex, pub_rand, _) = get_public_randomness_commitment();
        let fp_btc_pk = hex::decode(&pk_hex).unwrap();
        let pub_rand_one = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let add_finality_signature_2 = get_add_finality_sig_2();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;
        let block_height = initial_height + proof.index.unsigned_abs();

        // Create mock environment
        let info = message_info(&Addr::unchecked("test"), &[]);

        // Test slash_finality_provider
        let msg = get_msg_equivocation_evidence(
            &info,
            &fp_btc_pk,
            block_height,
            &pub_rand_one,
            &add_finality_signature.block_app_hash,
            &add_finality_signature.finality_sig,
            &add_finality_signature_2.block_app_hash,
            &add_finality_signature_2.finality_sig,
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
                assert_eq!(signer, "test");
                assert_eq!(fp_btc_pk_hex, hex::encode(&fp_btc_pk));
                assert_eq!(msg_height, block_height);
                assert_eq!(pub_rand_hex, hex::encode(&pub_rand_one));
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
}
