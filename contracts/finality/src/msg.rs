use crate::state::finality::Evidence;
use babylon_merkle::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary, CosmosMsg};

#[cfg(not(target_arch = "wasm32"))]
use {
    crate::state::config::Config, crate::state::public_randomness::PubRandCommit,
    cw_controllers::AdminResponse, std::collections::HashSet,
};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: String,
    pub consumer_id: String,
    pub is_enabled: bool,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // MUST: Core finality queries
    #[returns(Option<HashSet<String>>)]
    BlockVoters { height: u64, hash: String },
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

    // SHOULD: Administrative queries
    #[returns(AdminResponse)]
    Admin {},
    #[returns(Config)]
    Config {},
    #[returns(bool)]
    IsEnabled {},
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
    /// signature to the Consumer chain.
    /// The signature is verified by the Consumer chain using the finality provider's public key
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    SubmitFinalitySignature {
        /// The BTC public key of the finality provider submitting the signature
        fp_pubkey_hex: String,
        /// Optional L1 block number (rollup-specific)
        l1_block_number: Option<u64>,
        /// Optional L1 block hash (rollup-specific)
        l1_block_hash: Option<String>,
        /// The block height this finality signature is for
        height: u64,
        /// The public randomness used for signing this block
        pub_rand: Binary,
        /// Merkle proof verifying that pub_rand was included in the earlier commitment
        proof: Proof,
        /// Hash of the block being finalized
        // FIXME: Rename to block_app_hash for consistency / clarity
        block_hash: Binary,
        /// Finality signature on (height || block_hash) signed by finality provider
        signature: Binary,
    },
    /// Slashing message.
    ///
    /// This message slashes a finality provider for misbehavior.
    /// The caller must provide evidence of the misbehavior in the form of an Evidence struct.
    /// If the evidence is valid, the finality contract will send the evidence to the Babylon
    /// Genesis chain for actual slashing.
    Slashing { sender: Addr, evidence: Evidence },

    // SHOULD: Administrative messages
    /// Set enabled status of the finality contract.
    ///
    /// This message can be called by the admin only.
    /// If disabled, the finality contract and the BTC staking finality will not be used
    /// by the rollup. Note this should be implemented in the rollup's finality gadget daemon
    /// program and is not enforced by the contract itself.
    SetEnabled { enabled: bool },
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
    /// EquivocationEvidence is the message sent to Babylon to notify it of consumer chain slashing.
    EquivocationEvidence {
        /// `signer` is the address submitting the evidence
        signer: String,
        /// `fp_btc_pk` is the BTC PK of the finality provider that casts this vote
        fp_btc_pk: Vec<u8>,
        /// `block_height` is the height of the conflicting blocks
        block_height: u64,
        /// `pub_rand` is the public randomness the finality provider has committed to.
        pub_rand: Vec<u8>,
        /// `canonical_app_hash` is the AppHash of the canonical block
        canonical_app_hash: Vec<u8>,
        /// `fork_app_hash` is the AppHash of the fork block
        fork_app_hash: Vec<u8>,
        /// `canonical_finality_sig` is the finality signature to the canonical block,
        /// where finality signature is an EOTS signature, i.e.,
        /// the `s` in a Schnorr signature `(r, s)`.
        /// `r` is the public randomness already committed by the finality provider.
        canonical_finality_sig: Vec<u8>,
        /// `fork_finality_sig` is the finality signature to the fork block,
        /// where finality signature is an EOTS signature.
        fork_finality_sig: Vec<u8>,
    },
}

// make BabylonMsg to implement CosmosMsg::CustomMsg
impl cosmwasm_std::CustomMsg for BabylonMsg {}

impl From<BabylonMsg> for CosmosMsg<BabylonMsg> {
    fn from(original: BabylonMsg) -> Self {
        CosmosMsg::Custom(original)
    }
}
