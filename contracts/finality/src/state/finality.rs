use crate::{error::ContractError, state::public_randomness::insert_pub_rand_value};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Storage;
use cw_storage_plus::Map;
use std::collections::HashSet;

/// Map of (block height, finality provider public key in hex) tuples to the finality signature for that block.
pub(crate) const FINALITY_SIGNATURES: Map<(u64, &str), FinalitySigInfo> =
    Map::new("finality_signatures");

/// Map of (block height, block hash) tuples to the list of signatories
/// (each identified by the BTC public key in hex) for that block.
pub(crate) const SIGNATORIES_BY_BLOCK_HASH: Map<(u64, &[u8]), HashSet<String>> =
    Map::new("signatories_by_block_hash");

/// FinalitySigInfo is a struct that contains the finality signature and
/// block hash for a given block height and fp
#[cw_serde]
pub(crate) struct FinalitySigInfo {
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
fn insert_signatory(
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

/// Inserts public randomness, finality sig, and signatory into storage.
/// Returns an error if any of the operations fail.
pub fn insert_pub_rand_and_finality_sig(
    storage: &mut dyn Storage,
    fp_btc_pk_hex: &str,
    height: u64,
    block_hash: &[u8],
    pub_rand: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // Save the finality signature
    // TODO: in the case of an existing finality signature,
    // we are overriding the existing finality signature.
    // https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/44
    FINALITY_SIGNATURES.save(
        storage,
        (height, fp_btc_pk_hex),
        &FinalitySigInfo {
            finality_sig: signature.to_vec(),
            block_hash: block_hash.to_vec(),
        },
    )?;

    // Store public randomness, which will error if a public randomness has already been
    // stored for this finality provider at this height.
    insert_pub_rand_value(storage, fp_btc_pk_hex, height, pub_rand)?;

    // Add the fp_btc_pk_hex to the set
    insert_signatory(storage, height, block_hash, fp_btc_pk_hex)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{state::public_randomness::PUB_RAND_VALUES, testutil::datagen::*};
    use cosmwasm_std::testing::mock_dependencies;

    #[test]
    fn test_insert_pub_rand_and_finality_sig() {
        let mut deps = mock_dependencies();
        let height = get_random_u64();
        let block_hash = get_random_block_hash();
        let pub_rand = get_random_block_hash();
        let signature = get_random_block_hash();
        let fp_btc_pk_hex = get_random_fp_pk_hex();

        // Insert the data
        insert_pub_rand_and_finality_sig(
            deps.as_mut().storage,
            &fp_btc_pk_hex,
            height,
            &block_hash,
            &pub_rand,
            &signature,
        )
        .unwrap();

        // Verify finality signature was stored correctly
        let finality_sig_info = FINALITY_SIGNATURES
            .load(deps.as_ref().storage, (height, &fp_btc_pk_hex))
            .unwrap();
        assert_eq!(finality_sig_info.finality_sig, signature);
        assert_eq!(finality_sig_info.block_hash, block_hash);

        // Verify public randomness was stored correctly
        let stored_pub_rand = PUB_RAND_VALUES
            .load(deps.as_ref().storage, (&fp_btc_pk_hex, height))
            .unwrap();
        assert_eq!(stored_pub_rand, pub_rand);

        // Verify signatory was added to the set
        let signatories = SIGNATORIES_BY_BLOCK_HASH
            .load(deps.as_ref().storage, (height, &block_hash))
            .unwrap();
        assert!(signatories.contains(&fp_btc_pk_hex));
        assert_eq!(signatories.len(), 1);

        // Test idempotency with same values
        let result = insert_pub_rand_and_finality_sig(
            deps.as_mut().storage,
            &fp_btc_pk_hex,
            height,
            &block_hash,
            &pub_rand,
            &signature,
        );
        assert!(result.is_ok());

        // Test error case: different public randomness for same height/provider
        let different_pub_rand = get_random_block_hash();
        let result = insert_pub_rand_and_finality_sig(
            deps.as_mut().storage,
            &fp_btc_pk_hex,
            height,
            &block_hash,
            &different_pub_rand,
            &signature,
        );
        assert!(result.is_err());
        match result {
            Err(ContractError::PubRandAlreadyExists(pk, h)) => {
                assert_eq!(pk, fp_btc_pk_hex);
                assert_eq!(h, height);
            }
            _ => panic!("Expected PubRandAlreadyExists error"),
        }
    }
}
