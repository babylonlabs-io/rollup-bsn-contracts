use hex::FromHexError;
use thiserror::Error;

use cosmwasm_std::StdError;
use cw_controllers::AdminError;

use babylon_merkle::error::MerkleError;

// Note: copied from contracts/btc-staking/src/error.rs
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("Failed to load finality signature: {0} at height {1}")]
    FailedToLoadFinalitySignature(String, u64),
    #[error("Failed to load signatories by block hash: {0} at height {1}")]
    FailedToLoadSignatories(String, u64),
    #[error("Empty signature from the delegator")]
    EmptySignature,
    #[error("EOTS error: {0}")]
    EotsError(#[from] eots::Error),
    #[error("Failed to verify signature: {0}")]
    FailedSignatureVerification(String),
    #[error("The chain has not reached the given height yet")]
    HeightTooHigh,
    #[error("{0}")]
    HexError(#[from] FromHexError),
    #[error("The inclusion proof for height {0} does not correspond to the given height ({1})")]
    InvalidFinalitySigHeight(u64, u64),
    #[error("Contract already has an open IBC channel")]
    IbcChannelAlreadyOpen {},
    #[error("The contract only supports ordered channels")]
    IbcUnorderedChannel {},
    #[error("Counterparty version must be `{version}`")]
    IbcInvalidCounterPartyVersion { version: String },
    #[error("IBC method is not supported")]
    IbcUnsupportedMethod {},
    #[error("IBC send timed out: dest: channel {0}, port {1}")]
    IbcTimeout(String, String),
    #[error("The total amount of public randomnesses in the proof ({0}) does not match the amount of public committed randomness ({1})")]
    InvalidFinalitySigAmount(u64, u64),
    #[error("The start height ({0}) has overlap with the height of the highest public randomness committed ({1})")]
    InvalidPubRandHeight(u64, u64),
    #[error("Invalid finality signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid num_pub_rand value: {0}. Must be at least 1 to prevent integer underflow")]
    InvalidNumPubRand(u64),
    #[error("Invalid min_pub_rand value: {0}. Must be at least 1")]
    InvalidMinPubRand(u64),
    #[error("Invalid bsn_activation_height value: {0}. Must be at least 1")]
    InvalidBsnActivationHeight(u64),
    #[error("Invalid finality_signature_interval value: {0}. Must be at least 1")]
    InvalidFinalitySignatureInterval(u64),
    #[error("System not activated yet. Current height: {0}, activation height: {1}")]
    BeforeSystemActivation(u64, u64),
    #[error(
        "Finality signature not at scheduled height. Height {0} not allowed with interval {1}"
    )]
    FinalitySignatureNotAtScheduledHeight(u64, u64),
    #[error("{0}")]
    MerkleError(#[from] MerkleError),
    #[error("Public randomness not found for finality provider {0} at height {1}")]
    MissingPubRandCommit(String, u64),
    #[error("Failed to load public randomness for finality provider {0} at height {1}")]
    FailedToLoadPubRand(String, u64),
    #[error("{0}")]
    PubRandCommitNotBTCTimestamped(String),
    #[error("{0}")]
    SecP256K1Error(String), // TODO: inherit errors from k256
    #[error("Failed to extract secret key: {0}")]
    SecretKeyExtractionError(String),
    #[error("Finality provider {0} has been slashed at Babylon height {1} and BTC height {2}")]
    SlashedFinalityProvider(String, u64, u64),
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("Admin error: {0}")]
    Admin(#[from] AdminError),
    #[error("Failed to query block voters for block {0} with hash {1}. {2}")]
    QueryBlockVoterError(u64, String, String),
    #[error("Finality provider not found for BSN {0} with pubkey {1}")]
    NotFoundFinalityProvider(String, String),
    #[error("Failed to query the voting power of the finality provider {0}")]
    FailedFetchVotingPower(String),
    #[error("Caller is not the admin")]
    Unauthorized,
    #[error("Public randomness already exists for finality provider {0} at height {1}")]
    PubRandAlreadyExists(String, u64),
    #[error("Duplicate signatory {0}")]
    DuplicateSignatory(String),
    #[error("Duplicated finality signature for finality provider {0} at height {1}")]
    DuplicatedFinalitySig(String, u64),
    #[error("Too few public randomness values: given {given}, required minimum {required}")]
    TooFewPubRand { given: u64, required: u64 },
    #[error("Block height overflow: start height {start_height} is equal or higher than (start height + num pub rand) {end_height}")]
    OverflowInBlockHeight { start_height: u64, end_height: u64 },
    #[error("Invalid commitment length: expected {expected} bytes, got {actual}")]
    InvalidCommitmentLength { expected: usize, actual: usize },
    #[error("Invalid signature length: expected {expected} bytes, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    #[error("Empty finality provider BTC public key")]
    EmptyFpBtcPubKey,
    #[error("Invalid consumer ID: {0}")]
    InvalidBsnId(String),
    #[error("Invalid rate limiting interval: {0}. Must be at least 1")]
    InvalidRateLimitingInterval(u64),
    #[error("Invalid max messages per interval: {0}. Must be at least 1")]
    InvalidMaxMsgsPerInterval(u32),
    #[error("Rate limit exceeded for finality provider {fp_btc_pk} with limit {limit}")]
    RateLimitExceeded { fp_btc_pk: String, limit: u32 },
}
