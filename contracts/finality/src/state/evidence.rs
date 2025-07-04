use crate::error::ContractError;
use crate::state::Bytes;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Storage;
use cw_storage_plus::Map;

/// Map of evidence by block height and FP public key in hex
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
/// If there's already an Evidence entry for the same key, return an error, as this
/// should not happen.
pub fn insert_evidence(
    storage: &mut dyn Storage,
    evidence: &Evidence,
) -> Result<(), ContractError> {
    let fp_btc_pk_hex = hex::encode(&evidence.fp_btc_pk);
    if EVIDENCES.has(storage, (evidence.block_height, &fp_btc_pk_hex)) {
        return Err(ContractError::EvidenceAlreadyExists(
            fp_btc_pk_hex,
            evidence.block_height,
        ));
    }
    EVIDENCES.save(storage, (evidence.block_height, &fp_btc_pk_hex), evidence)?;
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

    #[test]
    fn test_set_and_get_evidence() {
        let mut deps = mock_dependencies();
        let height = get_random_u64();
        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let evidence = get_random_evidence(height, &fp_btc_pk_hex);
        // Store evidence
        insert_evidence(deps.as_mut().storage, &evidence).unwrap();
        // Try to store again and expect an error
        assert_eq!(
            insert_evidence(deps.as_mut().storage, &evidence).unwrap_err(),
            ContractError::EvidenceAlreadyExists(fp_btc_pk_hex.clone(), height)
        );
        // Retrieve evidence
        let loaded = get_evidence(deps.as_ref().storage, height, &fp_btc_pk_hex)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, evidence);
    }

    #[test]
    fn test_get_evidence_none_if_not_present() {
        let deps = mock_dependencies();
        let height = get_random_u64();
        let fp_btc_pk_hex = get_random_fp_pk_hex();
        let loaded = get_evidence(deps.as_ref().storage, height, &fp_btc_pk_hex).unwrap();
        assert!(loaded.is_none());
    }
}
