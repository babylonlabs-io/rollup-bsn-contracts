use crate::error::ContractError;
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::finality::BLOCK_VOTES;
use crate::state::public_randomness::get_pub_rand_commit;
use crate::state::public_randomness::PubRandCommit;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::AdminResponse;
use std::collections::HashSet;

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_voters(
    deps: Deps,
    height: u64,
    hash_hex: String,
) -> Result<Option<HashSet<String>>, ContractError> {
    let block_hash_bytes: Vec<u8> = hex::decode(&hash_hex).map_err(ContractError::HexError)?;
    // find all FPs that voted for this (height, hash_hex) combination
    let fp_pubkey_hex_list = BLOCK_VOTES
        .may_load(deps.storage, (height, &block_hash_bytes))
        .map_err(|e| {
            ContractError::QueryBlockVoterError(
                height,
                hash_hex.clone(),
                format!("Original error: {:?}", e),
            )
        })?;
    Ok(fp_pubkey_hex_list)
}

pub fn query_first_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(false))?;
    Ok(res.into_iter().next())
}

pub fn query_last_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(true))?;
    Ok(res.into_iter().next())
}

pub fn query_is_enabled(deps: Deps) -> StdResult<bool> {
    IS_ENABLED.load(deps.storage)
}

pub fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}
