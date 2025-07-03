use crate::error::ContractError;
use crate::state::Bytes;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Storage;
use cw_storage_plus::Map;

/// Map of evidence by block height and fp
pub(crate) const EVIDENCES: Map<(u64, &str), Evidence> = Map::new("evidences");

/// Evidence is the evidence that a finality provider has signed finality
/// signatures with correct public randomness on two conflicting Babylon headers
#[cw_serde]
pub struct Evidence {
    /// `fp_btc_pk` is the BTC PK of the finality provider that casts this vote
    pub fp_btc_pk: Bytes,
    /// `block_height` is the height of the conflicting blocks
    pub block_height: u64,
    /// `pub_rand` is the public randomness the finality provider has committed to.
    /// Deserializes to `SchnorrPubRand`
    pub pub_rand: Bytes,
    /// `canonical_app_hash` is the AppHash of the canonical block
    pub canonical_app_hash: Bytes,
    /// `fork_app_hash` is the AppHash of the fork block
    pub fork_app_hash: Bytes,
    /// `canonical_finality_sig` is the finality signature to the canonical block,
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`.
    /// `r` is the public randomness already committed by the finality provider.
    /// Deserializes to `SchnorrEOTSSig`
    pub canonical_finality_sig: Bytes,
    /// `fork_finality_sig` is the finality signature to the fork block,
    /// where finality signature is an EOTS signature.
    /// Deserializes to `SchnorrEOTSSig`
    pub fork_finality_sig: Bytes,
}

/// Stores an Evidence object in the EVIDENCES map for the given height and finality provider.
/// If there's already an  Evidence entry for the same key, return an error, as this
/// should not happen.
pub fn set_evidence(
    storage: &mut dyn Storage,
    height: u64,
    fp_btc_pk_hex: &str,
    evidence: &Evidence,
) -> Result<(), ContractError> {
    if EVIDENCES.has(storage, (height, fp_btc_pk_hex)) {
        return Err(ContractError::EvidenceAlreadyExists(
            fp_btc_pk_hex.to_string(),
            height,
        ));
    }
    EVIDENCES.save(storage, (height, fp_btc_pk_hex), evidence)?;
    Ok(())
}

/// Retrieves an Evidence object from the EVIDENCES map for the given height and finality provider.
pub fn get_evidence(
    storage: &dyn Storage,
    height: u64,
    fp_btc_pk_hex: &str,
) -> Result<Option<Evidence>, ContractError> {
    Ok(EVIDENCES.may_load(storage, (height, fp_btc_pk_hex))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;
    use rand::{thread_rng, Rng};

    /// Get a random evidence for a given height and finality provider.
    /// We are adding it here instead of datagen.rs as it is only used here.
    /// NOTE: The result is a mocked result, the signatures are not valid.
    fn get_random_evidence(height: u64, fp_btc_pk_hex: &str) -> Evidence {
        Evidence {
            fp_btc_pk: hex::decode(fp_btc_pk_hex).unwrap_or_else(|_| vec![0; 33]),
            block_height: height,
            pub_rand: get_random_pub_rand(),
            canonical_app_hash: get_random_block_hash(),
            fork_app_hash: get_random_block_hash(),
            canonical_finality_sig: (0..64).map(|_| rand::random()).collect(),
            fork_finality_sig: (0..64).map(|_| rand::random()).collect(),
        }
    }

    #[test]
    fn test_set_and_get_evidence() {
        let mut deps = mock_dependencies();
        let height = thread_rng().gen_range(1..1000);
        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let evidence = get_random_evidence(height, &fp_btc_pk_hex);
        // Store evidence
        set_evidence(deps.as_mut().storage, height, &fp_btc_pk_hex, &evidence).unwrap();
        // Try to store again and expect an error
        let err =
            set_evidence(deps.as_mut().storage, height, &fp_btc_pk_hex, &evidence).unwrap_err();
        match err {
            ContractError::EvidenceAlreadyExists(ref pk, h) => {
                assert_eq!(pk, &fp_btc_pk_hex);
                assert_eq!(h, height);
            }
            _ => panic!("Expected EvidenceAlreadyExists error, got {:?}", err),
        }
        // Retrieve evidence
        let loaded = get_evidence(deps.as_ref().storage, height, &fp_btc_pk_hex).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.fp_btc_pk, evidence.fp_btc_pk);
        assert_eq!(loaded.block_height, evidence.block_height);
        assert_eq!(loaded.pub_rand, evidence.pub_rand);
        assert_eq!(loaded.canonical_app_hash, evidence.canonical_app_hash);
        assert_eq!(loaded.fork_app_hash, evidence.fork_app_hash);
        assert_eq!(
            loaded.canonical_finality_sig,
            evidence.canonical_finality_sig
        );
        assert_eq!(loaded.fork_finality_sig, evidence.fork_finality_sig);
    }

    #[test]
    fn test_get_evidence_none_if_not_present() {
        let deps = mock_dependencies();
        let height = thread_rng().gen_range(1..1000);
        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let loaded = get_evidence(deps.as_ref().storage, height, &fp_btc_pk_hex).unwrap();
        assert!(loaded.is_none());
    }
}
