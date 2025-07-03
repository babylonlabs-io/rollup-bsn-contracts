use crate::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Deps;
use cosmwasm_std::Storage;
use cw_storage_plus::Map;
use std::collections::HashSet;

use crate::{error::ContractError, state::Bytes};

/// Map of (block height, block hash) tuples to the finality signature for that block.
pub(crate) const FINALITY_SIGNATURES: Map<(u64, &str), FinalitySigInfo> =
    Map::new("finality_signatures");

/// Map of (block height, block hash) tuples to the list of signatories
/// (each identified by the BTC public key in hex) for that block.
pub(crate) const SIGNATORIES_BY_BLOCK_HASH: Map<(u64, &[u8]), HashSet<String>> =
    Map::new("signatories_by_block_hash");

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

/// FinalitySigInfo is a struct that contains the finality signature and
/// block hash for a given block height and fp
#[cw_serde]
pub struct FinalitySigInfo {
    /// the finality signature
    pub finality_sig: Vec<u8>,
    /// the block hash that the finality signature is for
    pub block_hash: Vec<u8>,
}

/// Inserts a signatory into the SIGNATORIES_BY_BLOCK_HASH map for the given height and block hash.
/// The function does not do any checks:
/// - If the signatory is already there, the set will remain the same.
/// - If the signatory is a new one, the caller is responsible for ensuring that they are
///   inserting the right one. An insertion without a corresponding entry for a finality provider
///   in the FINALITY_SIGNATURES or PUB_RAND_VALUES storage might point to a storage corruption.
///   TODO: Should we have checks to avoid the above storage corruption situation?
pub fn insert_signatory(
    storage: &mut dyn Storage,
    height: u64,
    block_hash: &[u8],
    signatory: &str,
) -> Result<(), ContractError> {
    let mut set = SIGNATORIES_BY_BLOCK_HASH
        .may_load(storage, (height, block_hash))?
        .unwrap_or_else(HashSet::new);
    set.insert(signatory.to_string());
    SIGNATORIES_BY_BLOCK_HASH.save(storage, (height, block_hash), &set)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;
    use rand::{thread_rng, Rng};
    use std::collections::HashSet;

    #[test]
    fn test_insert_signatory_adds_to_set() {
        let mut deps = mock_dependencies();
        let height = thread_rng().gen_range(1..1000);
        let block_hash = get_random_block_hash();
        let num_signatories = thread_rng().gen_range(1..=20);
        let mut signatories_set = HashSet::new();
        while signatories_set.len() < num_signatories {
            signatories_set.insert(get_random_fp_pk_hex());
        }
        let signatories: Vec<_> = signatories_set.into_iter().collect();
        for signatory in &signatories {
            insert_signatory(deps.as_mut().storage, height, &block_hash, signatory).unwrap();
        }
        // Check that all signatories are present
        let set = SIGNATORIES_BY_BLOCK_HASH
            .load(deps.as_ref().storage, (height, &block_hash))
            .unwrap();
        for signatory in &signatories {
            assert!(set.contains(signatory));
        }
        assert_eq!(set.len(), num_signatories);
    }
}
