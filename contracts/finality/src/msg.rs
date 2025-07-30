use crate::error::ContractError;
use crate::validation::{
    validate_bsn_id, validate_finality_signature_interval, validate_max_msgs_per_interval,
    validate_min_pub_rand, validate_rate_limiting_interval,
};
use babylon_merkle::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, CosmosMsg};

#[cfg(not(target_arch = "wasm32"))]
use {
    crate::queries::BlockVoterInfo, crate::state::config::Config,
    crate::state::public_randomness::PubRandCommit, cw_controllers::AdminResponse,
};

/// Contract instantiation message containing all configuration parameters.
#[cw_serde]
pub struct InstantiateMsg {
    /// Initial admin address for the contract who can update settings
    pub admin: String,
    /// Unique identifier for the BSN (Bitcoin Supercharged Network) this
    /// contract secures
    pub bsn_id: String,
    /// Minimum number of public randomness values required in commitments
    pub min_pub_rand: u64,
    /// Number of Babylon blocks in each interval
    pub rate_limiting_interval: u64,
    /// Maximum messages allowed per finality provider per interval
    pub max_msgs_per_interval: u32,
    /// Rollup block height at which the BSN system is activated (0 =
    /// immediate activation). Only affects `SubmitFinalitySignature` messages.
    pub bsn_activation_height: u64,
    /// Interval between allowed finality signature submissions. Signatures can
    /// only be submitted at rollup block heights where `(height -
    /// bsn_activation_height) % interval == 0`.
    #[schemars(range(min = 1))]
    pub finality_signature_interval: u64,
    /// Optional list of BTC public keys (hex) to pre-populate the allowlist at
    /// instantiation
    pub allowed_finality_providers: Option<Vec<String>>,
}

impl InstantiateMsg {
    pub fn validate(&self) -> Result<(), ContractError> {
        // Validate min_pub_rand
        validate_min_pub_rand(self.min_pub_rand)?;
        // Validate BSN ID format
        validate_bsn_id(&self.bsn_id)?;
        // Validate rate limiting settings
        validate_rate_limiting_interval(self.rate_limiting_interval)?;
        validate_max_msgs_per_interval(self.max_msgs_per_interval)?;
        // Validate finality signature interval
        validate_finality_signature_interval(self.finality_signature_interval)?;

        Ok(())
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // MUST: Core finality queries
    #[returns(Vec<BlockVoterInfo>)]
    BlockVoters { height: u64, hash_hex: String },
    /// `FirstPubRandCommit` returns the first public random commitment (if any) for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    FirstPubRandCommit { btc_pk_hex: String },
    /// `LastPubRandCommit` returns the last public random commitment (if any) for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    LastPubRandCommit { btc_pk_hex: String },
    /// `ListPubRandCommit` returns a list of public randomness commitments for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// `start_after` is optional pagination parameter - only return commitments with start_height > start_after.
    /// `limit` is optional limit on number of results (default 10, max 30).
    /// `reverse` is optional flag to reverse the order (default false = ascending by start_height).
    #[returns(Vec<PubRandCommit>)]
    ListPubRandCommit {
        btc_pk_hex: String,
        start_after: Option<u64>,
        limit: Option<u32>,
        reverse: Option<bool>,
    },
    /// `HighestVotedHeight` returns the highest rollup block height that the given finality provider has voted on.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// Returns None if the finality provider has never submitted a finality signature.
    #[returns(Option<u64>)]
    HighestVotedHeight { btc_pk_hex: String },

    // SHOULD: Administrative queries
    #[returns(AdminResponse)]
    Admin {},
    #[returns(Config)]
    Config {},
    /// Get the list of all allowed finality providers.
    ///
    /// Returns a list of BTC public keys (in hex format) of finality providers
    /// that are allowed to submit finality signatures and public randomness commitments.
    #[returns(Vec<String>)]
    AllowedFinalityProviders {},
}

// Note: Adapted from packages/apis/src/btc_staking_api.rs / packages/apis/src/finality_api.rs
#[cw_serde]
pub enum ExecuteMsg {
    // MUST: Core finality messages
    /// This message allows a finality provider to commit to a sequence of public randomness values
    /// that will be revealed later during finality signature submissions.
    ///
    /// The commitment is a Merkle root containing the public randomness values. When submitting
    /// finality signatures later, the provider must include Merkle proofs that verify against this
    /// commitment.
    ///
    /// This commitment mechanism ensures that finality providers cannot adaptively choose their
    /// public randomness values after seeing block contents, which is important for security.
    CommitPublicRandomness {
        /// `fp_pubkey_hex` is the BTC PK of the finality provider that commits the public randomness
        fp_pubkey_hex: String,
        /// `start_height` is the start block height of the list of public randomness
        start_height: u64,
        /// `num_pub_rand` is the amount of public randomness committed
        num_pub_rand: u64,
        /// `commitment` is the commitment of these public randomness values.
        /// Currently, it's the root of the Merkle tree that includes the public randomness
        commitment: Binary,
        /// `signature` is the signature on (start_height || num_pub_rand || commitment) signed by
        /// the SK corresponding to `fp_pubkey_hex`.
        /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
        signature: Binary,
    },
    /// Submit Finality Signature.
    ///
    /// This is a message that can be called by a finality provider to submit their finality
    /// signature to the BSN.
    /// The signature is verified by the BSN using the finality provider's public key.
    /// If the finality provider has already signed a different block at the same height,
    /// they will be slashed by sending an equivocation evidence to Babylon Genesis.
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    SubmitFinalitySignature {
        /// The BTC public key of the finality provider submitting the signature
        fp_pubkey_hex: String,
        /// Optional L1 block number (rollup-specific)
        l1_block_number: Option<u64>,
        /// Optional L1 block hash hex (rollup-specific)
        l1_block_hash_hex: Option<String>,
        /// The block height this finality signature is for
        height: u64,
        /// The public randomness used for signing this block
        pub_rand: Binary,
        /// Merkle proof verifying that pub_rand was included in the earlier commitment
        proof: Proof,
        /// Hash of the block being finalized
        block_hash: Binary,
        /// Finality signature on (height || block_hash) signed by finality provider
        signature: Binary,
    },

    // SHOULD: Administrative messages
    /// Update the admin address.
    ///
    /// This message can be called by the admin only.
    /// The new admin address must be a valid Cosmos address.
    UpdateAdmin { admin: String },
    /// Prune old data (finality signatures, signatories by block hash, and public randomness values).
    ///
    /// This message can be called by the admin only.
    /// It removes old data for rollup blocks with height <= rollup_height.
    ///
    /// WARNING: This operation is irreversible. The admin is responsible for ensuring
    /// that the pruning height is safe and that no data is still being used
    /// for the affected height range.
    PruneData {
        /// Remove all data for rollup blocks with height <= this value.
        /// The admin should ensure this height provides sufficient safety margin
        /// for chain reorganizations and data submission delays.
        rollup_height: u64,
        /// Maximum number of finality signatures and signatories to prune in a single operation.
        /// Since every signature has a corresponding signatory record, this limit applies to both.
        /// This prevents gas exhaustion when there are many old entries.
        /// If not provided, the default value is 50.
        max_signatures_to_prune: Option<u32>,
        /// Maximum number of public randomness values to prune in a single operation.
        /// This prevents gas exhaustion when there are many old values.
        /// If not provided, the default value is 50.
        max_pub_rand_values_to_prune: Option<u32>,
    },
    /// Add a finality provider to the allowlist.
    ///
    /// This message can be called by the admin only.
    /// Only finality providers in the allowlist can submit finality signatures and public randomness commitments.
    AddToAllowlist {
        /// The BTC public keys of the finality providers to add to the allowlist (in hex format)
        fp_pubkey_hex_list: Vec<String>,
    },
    /// Remove a finality provider from the allowlist.
    ///
    /// This message can be called by the admin only.
    /// Removing a finality provider from the allowlist will prevent them from submitting
    /// new finality signatures and public randomness commitments.
    RemoveFromAllowlist {
        /// The BTC public keys of the finality providers to remove from the allowlist (in hex format)
        fp_pubkey_hex_list: Vec<String>,
    },
    /// Update contract configuration.
    ///
    /// This message can be called by the admin only.
    /// All fields are optional - only provided fields will be updated.
    /// Updated values must pass the same validation as during instantiation.
    UpdateConfig {
        /// New minimum number of public randomness values required (if provided)
        min_pub_rand: Option<u64>,
        /// New maximum messages per finality provider per interval (if provided)
        max_msgs_per_interval: Option<u32>,
        /// New rate limiting interval in blocks (if provided)
        rate_limiting_interval: Option<u64>,
        /// New BSN activation height (if provided)
        bsn_activation_height: Option<u64>,
        /// New finality signature interval (if provided)
        finality_signature_interval: Option<u64>,
    },
}

#[cw_serde]
pub struct FinalitySignatureResponse {
    pub signature: Vec<u8>,
}

/// Messages that the finality contract can send to Babylon node's Cosmos SDK layer
#[cw_serde]
pub enum BabylonMsg {
    /// MsgEquivocationEvidence is the message sent to Babylon for slashing an equivocating
    /// BSN finality provider.
    MsgEquivocationEvidence {
        /// `signer` is the address submitting the evidence
        signer: String,
        /// `fp_btc_pk_hex` is the BTC PK of the finality provider that casts this vote
        fp_btc_pk_hex: String,
        /// `block_height` is the height of the conflicting blocks
        block_height: u64,
        /// `pub_rand_hex` is the public randomness the finality provider has committed to.
        pub_rand_hex: String,
        /// `canonical_app_hash_hex` is the AppHash of the canonical block
        canonical_app_hash_hex: String,
        /// `fork_app_hash_hex` is the AppHash of the fork block
        fork_app_hash_hex: String,
        /// `canonical_finality_sig_hex` is the finality signature to the canonical block
        canonical_finality_sig_hex: String,
        /// `fork_finality_sig_hex` is the finality signature to the fork block
        fork_finality_sig_hex: String,
        /// `signing_context` is the context in which the finality signatures were used
        signing_context: String,
    },
}

// make BabylonMsg to implement CosmosMsg::CustomMsg
impl cosmwasm_std::CustomMsg for BabylonMsg {}

impl From<BabylonMsg> for CosmosMsg<BabylonMsg> {
    fn from(original: BabylonMsg) -> Self {
        CosmosMsg::Custom(original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instantiate_msg_validation_rate_limiting_interval_zero() {
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: "valid-bsn_123".to_string(),
            min_pub_rand: 1,
            rate_limiting_interval: 0,
            max_msgs_per_interval: 10,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };

        let err = msg.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidRateLimitingInterval(0)));
    }

    #[test]
    fn test_instantiate_msg_validation_max_msgs_per_interval_zero() {
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: "valid-bsn_123".to_string(),
            min_pub_rand: 1,
            rate_limiting_interval: 1000,
            max_msgs_per_interval: 0,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };

        let err = msg.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidMaxMsgsPerInterval(0)));
    }

    #[test]
    fn test_instantiate_msg_validation_min_pub_rand() {
        // Test with random min_pub_rand values
        for min_pub_rand in [0, 1, 100, 1000000] {
            let msg = InstantiateMsg {
                admin: "cosmos1admin".to_string(),
                bsn_id: "op-stack-l2-11155420".to_string(),
                min_pub_rand,
                rate_limiting_interval: 10000,
                max_msgs_per_interval: 100,
                bsn_activation_height: 0,
                finality_signature_interval: 1,
                allowed_finality_providers: None,
            };

            let result = msg.validate();

            if min_pub_rand > 0 {
                assert!(
                    result.is_ok(),
                    "Expected success for min_pub_rand = {min_pub_rand}"
                );
            } else {
                assert!(result.is_err(), "Expected error for min_pub_rand = 0");
                assert_eq!(result.unwrap_err(), ContractError::InvalidMinPubRand(0));
            }
        }
    }

    #[test]
    fn test_instantiate_msg_validation_invalid_bsn_id() {
        let invalid_bsn_id = "invalid@bsn#id"; // Contains invalid characters
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: invalid_bsn_id.to_string(),
            min_pub_rand: 100,
            rate_limiting_interval: 10000,
            max_msgs_per_interval: 100,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };

        let err = msg.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_instantiate_msg_validation_empty_bsn_id() {
        let empty_bsn_id = "";
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: empty_bsn_id.to_string(),
            min_pub_rand: 100,
            rate_limiting_interval: 10000,
            max_msgs_per_interval: 100,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };

        let err = msg.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_instantiate_msg_validation_valid_bsn_id() {
        let valid_bsn_ids = vec![
            "op-stack-l2-11155420",
            "valid-bsn_123",
            "test_chain",
            "chain-1",
            "abc123",
        ];

        for bsn_id in valid_bsn_ids {
            let msg = InstantiateMsg {
                admin: "cosmos1admin".to_string(),
                bsn_id: bsn_id.to_string(),
                min_pub_rand: 100,
                rate_limiting_interval: 10000,
                max_msgs_per_interval: 100,
                bsn_activation_height: 0,
                finality_signature_interval: 1,
                allowed_finality_providers: None,
            };

            let result = msg.validate();
            assert!(result.is_ok(), "Expected success for bsn_id = {bsn_id}");
        }
    }

    #[test]
    fn test_instantiate_msg_validation_bsn_id_length() {
        // Test maximum length
        let long_bsn_id = "a".repeat(crate::validation::MAX_BSN_ID_LENGTH);
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: long_bsn_id,
            min_pub_rand: 100,
            rate_limiting_interval: 10000,
            max_msgs_per_interval: 100,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };
        assert!(msg.validate().is_ok());

        // Test exceeding maximum length
        let too_long_bsn_id = "a".repeat(crate::validation::MAX_BSN_ID_LENGTH + 1);
        let msg = InstantiateMsg {
            admin: "cosmos1admin".to_string(),
            bsn_id: too_long_bsn_id,
            min_pub_rand: 100,
            rate_limiting_interval: 10000,
            max_msgs_per_interval: 100,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }
}
