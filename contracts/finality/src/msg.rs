use babylon_merkle::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, CosmosMsg};

#[cfg(not(target_arch = "wasm32"))]
use {
    crate::queries::BlockVoterInfo, crate::state::config::Config,
    crate::state::public_randomness::PubRandCommit, cw_controllers::AdminResponse,
};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: String,
    pub bsn_id: String,
    pub min_pub_rand: u64,
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
    /// `ListPubRandCommit` returns a list of public random commitments for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// `start_after` is optional and can be used for pagination.
    /// `limit` is optional and defaults to 10, max 30.
    /// `reverse` is optional and defaults to false.
    #[returns(Vec<PubRandCommit>)]
    ListPubRandCommit {
        btc_pk_hex: String,
        start_after: Option<u64>,
        limit: Option<u32>,
        reverse: Option<bool>,
    },

    // SHOULD: Administrative queries
    #[returns(AdminResponse)]
    Admin {},
    #[returns(Config)]
    Config {},
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
