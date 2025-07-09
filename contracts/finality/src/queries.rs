use babylon_bindings::BabylonQuery;
use cosmwasm_std::Deps;

use crate::error::ContractError;
use crate::state::finality::get_finality_signature;
use crate::state::finality::get_signatories_by_block_hash;
use crate::state::finality::FinalitySigInfo;
use crate::state::public_randomness::PUB_RAND_VALUES;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct BlockVoterInfo {
    pub fp_btc_pk_hex: String,
    pub pub_rand: Vec<u8>,
    pub finality_signature: FinalitySigInfo,
}

pub fn query_block_voters(
    deps: Deps<BabylonQuery>,
    height: u64,
    hash_hex: String,
) -> Result<Option<Vec<BlockVoterInfo>>, ContractError> {
    let block_hash_bytes: Vec<u8> = hex::decode(&hash_hex).map_err(ContractError::HexError)?;
    let fp_pubkey_hex_set = get_signatories_by_block_hash(deps.storage, height, &block_hash_bytes)
        .map_err(|e| {
            ContractError::QueryBlockVoterError(
                height,
                hash_hex.clone(),
                format!("Original error: {e:?}"),
            )
        })?;
    if let Some(set) = fp_pubkey_hex_set {
        let mut result = Vec::with_capacity(set.len());
        for fp_btc_pk_hex in set.iter() {
            let fp_btc_pk = hex::decode(fp_btc_pk_hex)?;
            let sig = get_finality_signature(deps.storage, height, &fp_btc_pk)?.ok_or(
                ContractError::QueryBlockVoterError(
                    height,
                    hash_hex.clone(),
                    format!("Missing FinalitySigInfo for FP {fp_btc_pk_hex}"),
                ),
            )?;

            let pub_rand = PUB_RAND_VALUES
                .may_load(deps.storage, (&fp_btc_pk, height))?
                .ok_or_else(|| {
                    ContractError::QueryBlockVoterError(
                        height,
                        hash_hex.clone(),
                        format!("Missing public randomness for FP {fp_btc_pk_hex}"),
                    )
                })?;

            result.push(BlockVoterInfo {
                fp_btc_pk_hex: hex::encode(fp_btc_pk),
                pub_rand,
                finality_signature: sig,
            });
        }
        Ok(Some(result))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use crate::{
        contract::tests::mock_deps_babylon, state::finality::insert_finality_sig_and_signatory,
    };
    use rand::{rng, Rng};
    use std::collections::HashSet;

    #[test]
    fn test_query_block_voters_returns_fp_and_signature() {
        let mut deps = mock_deps_babylon();
        let height = 42u64;
        let block_hash: Vec<u8> = get_random_block_hash();
        let block_hash_hex = hex::encode(&block_hash);
        let mut rng = rng();
        let num_fps = rng.random_range(1..=10);
        let mut set = HashSet::new();
        let mut expected: Vec<(String, Vec<u8>, FinalitySigInfo)> = Vec::new();
        for _ in 0..num_fps {
            let fp_btc_pk = get_random_fp_pk();
            let fp_btc_pk_hex = hex::encode(fp_btc_pk.clone());
            let sig = get_random_finality_sig(&block_hash);
            let pub_rand = get_random_pub_rand();
            set.insert(fp_btc_pk_hex.clone());
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &sig.finality_sig,
            )
            .unwrap();
            PUB_RAND_VALUES
                .save(deps.as_mut().storage, (&fp_btc_pk, height), &pub_rand)
                .unwrap();
            expected.push((fp_btc_pk_hex, pub_rand, sig));
        }
        let result = query_block_voters(deps.as_ref(), height, block_hash_hex).unwrap();
        let voters = result.expect("should have voters");
        assert_eq!(voters.len(), num_fps);
        // Check all expected FPs and signatures are present
        for (fp, pub_rand, sig) in expected {
            let found = voters.iter().find(|v| v.fp_btc_pk_hex == fp);
            assert!(found.is_some(), "FP {fp} not found in voters");
            let found = found.unwrap();
            assert_eq!(found.pub_rand, pub_rand);
            assert_eq!(found.finality_signature.finality_sig, sig.finality_sig);
            assert_eq!(found.finality_signature.block_hash, sig.block_hash);
        }
    }
}
