use babylon_bindings::BabylonQuery;
use cosmwasm_std::{Deps, Env, StdResult};
use k256::sha2::{Digest, Sha256};

use crate::state::config::get_config;

const PROTOCOL_NAME: &str = "btcstaking";
const VERSION_V0: &str = "0";
const FP_RAND_COMMIT: &str = "fp_rand_commit";
const FP_FIN_VOTE: &str = "fp_fin_vote";

fn btc_staking_v0_context(operation_tag: &str, chain_id: &str, address: &str) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        PROTOCOL_NAME, VERSION_V0, operation_tag, chain_id, address
    )
}

/// Returns the hex encoded sha256 hash of the context string i.e
/// hex(sha256(context_string))
fn hashed_hex_context(context_string: &str) -> String {
    let hash = Sha256::digest(context_string.as_bytes());
    hex::encode(hash)
}

/// Returns context string in format:
/// btcstaking/0/fp_rand_commit/{chain_id}/{address}
fn fp_rand_commit_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_RAND_COMMIT, chain_id, address))
}

/// Returns context string in format:
/// btcstaking/0/fp_fin_vote/{chain_id}/{address}
fn fp_fin_vote_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_FIN_VOTE, chain_id, address))
}

pub fn get_fp_rand_commit_context_v0(deps: Deps<BabylonQuery>, env: &Env) -> StdResult<String> {
    let bsn_id = get_config(deps)?.bsn_id;
    let address = env.contract.address.to_string();
    Ok(fp_rand_commit_context_v0(&bsn_id, &address))
}

pub fn get_fp_fin_vote_context_v0(deps: Deps<BabylonQuery>, env: &Env) -> StdResult<String> {
    let bsn_id = get_config(deps)?.bsn_id;
    let address = env.contract.address.to_string();
    Ok(fp_fin_vote_context_v0(&bsn_id, &address))
}
