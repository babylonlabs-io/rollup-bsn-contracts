use crate::error::ContractError;
use anybuf::{Anybuf, Bufany};
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{Binary, Deps, Env, StdResult};
use k256::sha2::{Digest, Sha256};

/// FinalityProviderResponse defines a finality provider with voting power information.
/// NOTE: this is a subset of the response from Babylon
pub struct FinalityProviderResponse {
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_btc_height: u64,
    // bsn_id is the ID of the BSN the finality provider is securing
    pub bsn_id: String,
}

pub fn query_finality_provider(
    deps: Deps<BabylonQuery>,
    fp_btc_pk_hex: String,
) -> StdResult<FinalityProviderResponse> {
    let query_data = Anybuf::new()
        .append_string(1, fp_btc_pk_hex.clone())
        .into_vec();

    let res_data: Binary = deps.querier.query_grpc(
        "/babylon.btcstaking.v1.Query/FinalityProvider".to_string(),
        Binary::new(query_data),
    )?;

    let res_decoded = Bufany::deserialize(&res_data).unwrap();
    // see https://github.com/babylonlabs-io/babylon/blob/main/proto/babylon/btcstaking/v1/query.proto
    // for protobuf definition
    let res_fp = res_decoded.message(1).unwrap();
    let res: FinalityProviderResponse = FinalityProviderResponse {
        slashed_babylon_height: res_fp.uint64(6).unwrap(),
        slashed_btc_height: res_fp.uint64(7).unwrap(),
        bsn_id: res_fp.string(12).unwrap(),
    };

    Ok(res)
}

const MAX_BSN_ID_LENGTH: usize = 100;

/// Validates that a BSN ID has a valid format (non-empty, valid characters, etc.)
pub fn validate_bsn_id_format(bsn_id: &str) -> Result<(), ContractError> {
    if bsn_id.is_empty() {
        return Err(ContractError::InvalidBsnId(
            "BSN ID cannot be empty".to_string(),
        ));
    }

    // Check for valid characters (alphanumeric, hyphens, underscores)
    if !bsn_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ContractError::InvalidBsnId(
            "BSN ID can only contain alphanumeric characters, hyphens, and underscores".to_string(),
        ));
    }

    // Check length (reasonable bounds)
    if bsn_id.len() > MAX_BSN_ID_LENGTH {
        return Err(ContractError::InvalidBsnId(
            "BSN ID cannot exceed {MAX_BSN_ID_LENGTH} characters".to_string(),
        ));
    }

    Ok(())
}

impl FinalityProviderResponse {
    /// Checks if this finality provider has been slashed based on the response from Babylon
    pub fn is_slashed(&self) -> bool {
        self.slashed_babylon_height != 0 || self.slashed_btc_height != 0
    }
}

/// Signing context library
const PROTOCOL_NAME: &str = "btcstaking";
const VERSION_V0: &str = "0";
const FP_RAND_COMMIT: &str = "fp_rand_commit";
const FP_FIN_VOTE: &str = "fp_fin_vote";

fn btc_staking_v0_context(operation_tag: &str, chain_id: &str, address: &str) -> String {
    format!("{PROTOCOL_NAME}/{VERSION_V0}/{operation_tag}/{chain_id}/{address}")
}

/// Returns the hex encoded sha256 hash of the context string i.e
/// hex(sha256(context_string))
fn hashed_hex_context(context_string: &str) -> String {
    let hash = Sha256::digest(context_string.as_bytes());
    hex::encode(hash)
}

/// Returns context string in format:
/// hex(sha256(btcstaking/0/fp_rand_commit/{chain_id}/{address}))
fn fp_rand_commit_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_RAND_COMMIT, chain_id, address))
}

/// Returns context string in format:
/// hex(sha256(btcstaking/0/fp_fin_vote/{chain_id}/{address}))
fn fp_fin_vote_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_FIN_VOTE, chain_id, address))
}

pub fn get_fp_rand_commit_context_v0(env: &Env) -> StdResult<String> {
    let chain_id = &env.block.chain_id;
    let address = env.contract.address.to_string();
    Ok(fp_rand_commit_context_v0(chain_id, &address))
}

pub fn get_fp_fin_vote_context_v0(env: &Env) -> StdResult<String> {
    let chain_id = &env.block.chain_id;
    let address = env.contract.address.to_string();
    Ok(fp_fin_vote_context_v0(chain_id, &address))
}
