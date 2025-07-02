use crate::error::ContractError;
use crate::state::config::{Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::finality::{FinalitySigInfo, FINALITY_SIGNATURES, SIGNATORIES_BY_BLOCK_HASH};
use crate::state::public_randomness::PubRandCommit;
use crate::state::public_randomness::{get_pub_rand_commit, PUB_RAND_VALUES};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_controllers::AdminResponse;

#[cw_serde]
pub struct BlockVoterInfo {
    pub fp_btc_pk_hex: String,
    pub pub_rand: Vec<u8>,
    pub finality_signature: FinalitySigInfo,
}

pub fn query_config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn query_block_voters(
    deps: Deps,
    height: u64,
    hash_hex: String,
) -> Result<Option<Vec<BlockVoterInfo>>, ContractError> {
    let block_hash_bytes: Vec<u8> = hex::decode(&hash_hex).map_err(ContractError::HexError)?;
    let fp_pubkey_hex_set = SIGNATORIES_BY_BLOCK_HASH
        .may_load(deps.storage, (height, &block_hash_bytes))
        .map_err(|e| {
            ContractError::QueryBlockVoterError(
                height,
                hash_hex.clone(),
                format!("Original error: {:?}", e),
            )
        })?;
    if let Some(set) = fp_pubkey_hex_set {
        let mut result = Vec::new();
        for fp_btc_pk_hex in set.iter() {
            let sig = FINALITY_SIGNATURES
                .may_load(deps.storage, (height, fp_btc_pk_hex.as_str()))?
                .ok_or_else(|| {
                    ContractError::QueryBlockVoterError(
                        height,
                        hash_hex.clone(),
                        format!("Missing FinalitySigInfo for FP {}", fp_btc_pk_hex),
                    )
                })?;

            let pub_rand = PUB_RAND_VALUES
                .may_load(deps.storage, (fp_btc_pk_hex.as_str(), height))?
                .ok_or_else(|| {
                    ContractError::QueryBlockVoterError(
                        height,
                        hash_hex.clone(),
                        format!("Missing public randomness for FP {}", fp_btc_pk_hex),
                    )
                })?;

            result.push(BlockVoterInfo {
                fp_btc_pk_hex: fp_btc_pk_hex.clone(),
                pub_rand,
                finality_signature: sig,
            });
        }
        Ok(Some(result))
    } else {
        Ok(None)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finality::{FinalitySigInfo, FINALITY_SIGNATURES, SIGNATORIES_BY_BLOCK_HASH};
    use crate::state::public_randomness::PUB_RAND_VALUES;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;
    use rand::{thread_rng, Rng};
    use std::collections::HashSet;

    #[test]
    fn test_query_block_voters_returns_fp_and_signature() {
        let mut deps = mock_dependencies();
        let height = 42u64;
        let block_hash: Vec<u8> = get_random_block_hash();
        let block_hash_hex = hex::encode(&block_hash);
        let mut rng = thread_rng();
        let num_fps = rng.gen_range(1..=10);
        let mut set = HashSet::new();
        let mut expected: Vec<(String, Vec<u8>, FinalitySigInfo)> = Vec::new();
        for _ in 0..num_fps {
            let fp_btc_pk_hex = get_random_fp_pk_hex();
            let sig = get_random_finality_sig(&block_hash);
            let pub_rand = get_random_pub_rand();
            set.insert(fp_btc_pk_hex.clone());
            FINALITY_SIGNATURES
                .save(
                    deps.as_mut().storage,
                    (height, fp_btc_pk_hex.as_str()),
                    &sig,
                )
                .unwrap();
            PUB_RAND_VALUES
                .save(
                    deps.as_mut().storage,
                    (fp_btc_pk_hex.as_str(), height),
                    &pub_rand,
                )
                .unwrap();
            expected.push((fp_btc_pk_hex, pub_rand, sig));
        }
        SIGNATORIES_BY_BLOCK_HASH
            .save(deps.as_mut().storage, (height, &block_hash), &set)
            .unwrap();
        let result = query_block_voters(deps.as_ref(), height, block_hash_hex).unwrap();
        let voters = result.expect("should have voters");
        assert_eq!(voters.len(), num_fps);
        // Check all expected FPs and signatures are present
        for (fp, pub_rand, sig) in expected {
            let found = voters.iter().find(|v| v.fp_btc_pk_hex == fp);
            assert!(found.is_some(), "FP {} not found in voters", fp);
            let found = found.unwrap();
            assert_eq!(found.pub_rand, pub_rand);
            assert_eq!(found.finality_signature.finality_sig, sig.finality_sig);
            assert_eq!(found.finality_signature.block_hash, sig.block_hash);
        }
    }
}
