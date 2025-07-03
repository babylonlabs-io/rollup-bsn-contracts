use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::CONFIG;
use crate::state::finality::{Evidence, BLOCK_HASHES, BLOCK_VOTES, EVIDENCES, SIGNATURES};
use crate::state::public_randomness::PubRandCommit;
use crate::state::public_randomness::{
    get_pub_rand_commit_for_height, insert_pub_rand_commit, PUB_RAND_VALUES,
};
use crate::utils::query_finality_provider;
use babylon_merkle::Proof;
use cosmwasm_std::{Deps, DepsMut, Env, Event, MessageInfo, Response};
use k256::ecdsa::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use std::collections::HashSet;

// Most logic copied from contracts/btc-staking/src/finality.rs
pub fn handle_public_randomness_commit(
    deps: DepsMut,
    env: &Env,
    fp_pubkey_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure the finality provider is registered and not slashed
    ensure_fp_exists_and_not_slashed(deps.as_ref(), fp_pubkey_hex)?;

    // Verify signature over the list
    verify_commitment_signature(
        fp_pubkey_hex,
        start_height,
        num_pub_rand,
        commitment,
        signature,
    )?;

    // insert the public randomness commitment into the storage
    // note that `insert_pub_rand_commit` has ensured that
    // - the new commitment does not overlap with the existing ones
    // - the new commitment does not have num_pub_rand = 0
    insert_pub_rand_commit(
        deps.storage,
        fp_pubkey_hex,
        PubRandCommit {
            start_height,
            num_pub_rand,
            height: env.block.height,
            commitment: commitment.to_vec(),
        },
    )?;

    let event = Event::new("public_randomness_commit")
        .add_attribute("fp_pubkey_hex", fp_pubkey_hex)
        .add_attribute("pr_commit.start_height", start_height.to_string())
        .add_attribute("pr_commit.num_pub_rand", num_pub_rand.to_string());

    Ok(Response::new().add_event(event))
}

// Copied from contracts/btc-staking/src/finality.rs
pub(crate) fn verify_commitment_signature(
    fp_btc_pk_hex: &str,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // get BTC public key for verification
    let btc_pk_raw = hex::decode(fp_btc_pk_hex)?;
    let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw)
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

// Most logic copied from contracts/btc-staking/src/finality.rs
#[allow(clippy::too_many_arguments)]
pub fn handle_finality_signature(
    deps: DepsMut,
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

    // NOTE: It's possible that the finality provider equivocates for height h, and the signature is
    // processed at height h' > h. In this case:
    // - We should reject any new signature from this finality provider, since it's known to be adversarial.
    // - We should set its voting power since height h'+1 to be zero, for to the same reason.
    // - We should NOT set its voting power between [h, h'] to be zero, since
    //   - Babylon BTC staking ensures safety upon 2f+1 votes, *even if* f of them are adversarial.
    //     This is because as long as a block gets 2f+1 votes, any other block with 2f+1 votes has a
    //     f+1 quorum intersection with this block, contradicting the assumption and leading to
    //     the safety proof.
    //     This ensures slashable safety together with EOTS, thus does not undermine Babylon's security guarantee.
    //   - Due to this reason, when tallying a block, Babylon finalises this block upon 2f+1 votes. If we
    //     modify voting power table in the history, some finality decisions might be contradicting to the
    //     signature set and voting power table.
    //   - To fix the above issue, Babylon has to allow finalised and not-finalised blocks. However,
    //     this means Babylon will lose safety under an adaptive adversary corrupting even 1
    //     finality provider. It can simply corrupt a new finality provider and equivocate a
    //     historical block over and over again, making a previous block not finalisable forever.

    // Ensure the finality provider has voting power at this height
    // TODO (lester): use gRPC to query the Babylon Chain

    // Ensure the signature is not empty
    if signature.is_empty() {
        return Err(ContractError::EmptySignature);
    }

    // Ensure the finality provider has not cast the same vote yet
    let existing_sig = SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    match existing_sig {
        Some(existing_sig) if existing_sig == signature => {
            deps.api.debug(&format!("Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return success to the provider
            return Ok(Response::new());
        }
        _ => {}
    }

    // Find the public randomness commitment for this height from this finality provider
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height)?;

    // Verify the finality signature message
    verify_finality_signature(
        fp_btc_pk_hex,
        height,
        pub_rand,
        proof,
        &pr_commit,
        block_hash,
        signature,
    )?;

    // The public randomness value is good, save it.
    // TODO?: Don't save public randomness values, to save storage space (#122)
    PUB_RAND_VALUES.save(deps.storage, (fp_btc_pk_hex, height), &pub_rand.to_vec())?;

    // Build the response
    let mut res: Response<BabylonMsg> = Response::new();

    // If this finality provider has signed a different block at the same height before,
    // create equivocation evidence and send it directly to Babylon Genesis for slashing
    let canonical_sig: Option<Vec<u8>> =
        SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    let canonical_block_hash: Option<Vec<u8>> =
        BLOCK_HASHES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    if let (Some(canonical_sig), Some(canonical_block_hash)) = (canonical_sig, canonical_block_hash)
    {
        // The finality provider has voted for a different block at the same height!
        // Create equivocation evidence and send it to Babylon Genesis for slashing

        // Construct evidence
        let evidence = Evidence {
            fp_btc_pk: hex::decode(fp_btc_pk_hex)?,
            block_height: height,
            pub_rand: pub_rand.to_vec(),
            canonical_app_hash: canonical_block_hash,
            canonical_finality_sig: canonical_sig,
            fork_app_hash: block_hash.to_vec(),
            fork_finality_sig: signature.to_vec(),
        };

        // Save evidence for future reference
        EVIDENCES.save(deps.storage, (height, fp_btc_pk_hex), &evidence)?;

        // slash this finality provider, including setting its voting power to
        // zero, extracting its BTC SK, and emit an event
        let (msg, ev) = slash_finality_provider(&info, &fp_btc_pk_hex, &evidence)?;
        res = res.add_message(msg).add_event(ev);
    }

    // This signature is good, save the vote to the store
    SIGNATURES.save(deps.storage, (height, fp_btc_pk_hex), &signature.to_vec())?;
    BLOCK_HASHES.save(deps.storage, (height, fp_btc_pk_hex), &block_hash.to_vec())?;

    // Check if the key (height, block_hash) exists
    let mut block_votes_fp_set = BLOCK_VOTES
        .may_load(deps.storage, (height, block_hash))?
        .unwrap_or_else(HashSet::new);

    // Add the fp_btc_pk_hex to the set
    block_votes_fp_set.insert(fp_btc_pk_hex.to_string());

    // Save the updated set back to storage
    BLOCK_VOTES.save(deps.storage, (height, block_hash), &block_votes_fp_set)?;

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

    Ok(res)
}

/// Verifies the finality signature message w.r.t. the public randomness commitment:
/// - Public randomness inclusion proof.
/// - Finality signature
pub(crate) fn verify_finality_signature(
    fp_btc_pk_hex: &str,
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
    let pubkey = eots::PublicKey::from_hex(fp_btc_pk_hex)?;
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

fn ensure_fp_exists_and_not_slashed(deps: Deps, fp_pubkey_hex: &str) -> Result<(), ContractError> {
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

/// `slash_finality_provider` slashes a finality provider with the given evidence including setting
/// its voting power to zero, extracting its BTC SK, and emitting an event
fn slash_finality_provider(
    info: &MessageInfo,
    fp_btc_pk_hex: &str,
    evidence: &Evidence,
) -> Result<(BabylonMsg, Event), ContractError> {
    let pk = eots::PublicKey::from_bytes(&evidence.fp_btc_pk)?;
    let btc_sk = pk
        .extract_secret_key(
            &evidence.pub_rand,
            &evidence.canonical_app_hash,
            &evidence.canonical_finality_sig,
            &evidence.fork_app_hash,
            &evidence.fork_finality_sig,
        )
        .map_err(|err| ContractError::SecretKeyExtractionError(err.to_string()))?;

    let msg = BabylonMsg::MsgEquivocationEvidence {
        signer: info.sender.to_string(),
        fp_btc_pk_hex: hex::encode(&evidence.fp_btc_pk),
        block_height: evidence.block_height,
        pub_rand_hex: hex::encode(&evidence.pub_rand),
        canonical_app_hash_hex: hex::encode(&evidence.canonical_app_hash),
        fork_app_hash_hex: hex::encode(&evidence.fork_app_hash),
        canonical_finality_sig_hex: hex::encode(&evidence.canonical_finality_sig),
        fork_finality_sig_hex: hex::encode(&evidence.fork_finality_sig),
        signing_context: "".to_string(), // TODO: support signing context
    };

    let ev = Event::new("slashed_finality_provider")
        .add_attribute("module", "finality")
        .add_attribute("finality_provider", fp_btc_pk_hex)
        .add_attribute("block_height", evidence.block_height.to_string())
        .add_attribute(
            "canonical_app_hash",
            hex::encode(&evidence.canonical_app_hash),
        )
        .add_attribute(
            "canonical_finality_sig",
            hex::encode(&evidence.canonical_finality_sig),
        )
        .add_attribute("fork_app_hash", hex::encode(&evidence.fork_app_hash))
        .add_attribute(
            "fork_finality_sig",
            hex::encode(&evidence.fork_finality_sig),
        )
        .add_attribute("secret_key", hex::encode(btc_sk.to_bytes()));
    Ok((msg, ev))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cosmwasm_std::{testing::message_info, Addr};
    use std::collections::HashMap;
    use test_utils::{
        get_add_finality_sig, get_add_finality_sig_2, get_pub_rand_value,
        get_public_randomness_commitment,
    };

    #[test]
    fn verify_commitment_signature_works() {
        // Define test values
        let (fp_btc_pk_hex, pr_commit, sig) = get_public_randomness_commitment();

        // Verify commitment signature
        let res = verify_commitment_signature(
            &fp_btc_pk_hex,
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

        // Convert the PubRandCommit in the type defined in this contract
        let pr_commit = PubRandCommit {
            start_height: pr_commit.start_height,
            num_pub_rand: pr_commit.num_pub_rand,
            height: pr_commit.height,
            commitment: pr_commit.commitment,
        };

        // Verify finality signature
        assert!(proof.index >= 0, "Proof index should be non-negative");
        let res = verify_finality_signature(
            &pk_hex,
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
        let pub_rand_one = get_pub_rand_value();
        let add_finality_signature = get_add_finality_sig();
        let add_finality_signature_2 = get_add_finality_sig_2();
        let proof = add_finality_signature.proof.unwrap();

        let initial_height = pub_rand.start_height;
        let block_height = initial_height + proof.index.unsigned_abs();

        // Create evidence struct
        let evidence = Evidence {
            fp_btc_pk: hex::decode(&pk_hex).unwrap(),
            block_height,
            pub_rand: pub_rand_one.to_vec(),
            canonical_app_hash: add_finality_signature.block_app_hash.to_vec(),
            canonical_finality_sig: add_finality_signature.finality_sig.to_vec(),
            fork_app_hash: add_finality_signature_2.block_app_hash.to_vec(),
            fork_finality_sig: add_finality_signature_2.finality_sig.to_vec(),
        };

        // Create mock environment
        let info = message_info(&Addr::unchecked("test"), &[]);

        // Test slash_finality_provider
        let (msg, event) = slash_finality_provider(&info, &pk_hex, &evidence).unwrap();

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
                assert_eq!(fp_btc_pk_hex, hex::encode(&evidence.fp_btc_pk));
                assert_eq!(msg_height, evidence.block_height);
                assert_eq!(pub_rand_hex, hex::encode(&evidence.pub_rand));
                assert_eq!(
                    canonical_app_hash_hex,
                    hex::encode(&evidence.canonical_app_hash)
                );
                assert_eq!(fork_app_hash_hex, hex::encode(&evidence.fork_app_hash));
                assert_eq!(
                    canonical_finality_sig_hex,
                    hex::encode(&evidence.canonical_finality_sig)
                );
                assert_eq!(
                    fork_finality_sig_hex,
                    hex::encode(&evidence.fork_finality_sig)
                );
                assert_eq!(signing_context, "");
            }
        }

        // Verify the event attributes
        assert_eq!(event.ty, "slashed_finality_provider");
        let attrs: HashMap<_, _> = event
            .attributes
            .iter()
            .map(|a| (a.key.clone(), a.value.clone()))
            .collect();
        assert_eq!(attrs.get("module").unwrap(), "finality");
        assert_eq!(attrs.get("finality_provider").unwrap(), &pk_hex);
        assert_eq!(
            attrs.get("block_height").unwrap(),
            &block_height.to_string()
        );
        assert_eq!(
            attrs.get("canonical_app_hash").unwrap(),
            &hex::encode(&evidence.canonical_app_hash)
        );
    }
}
