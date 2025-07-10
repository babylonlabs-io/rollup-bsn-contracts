use crate::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::Map;
use std::collections::HashSet;

/// Map of (block height, finality provider public key) tuples to the finality signature for that block.
const FINALITY_SIGNATURES: Map<(u64, &[u8]), FinalitySigInfo> = Map::new("finality_signatures");

pub fn get_finality_signature(
    storage: &dyn Storage,
    height: u64,
    fp_btc_pk: &[u8],
) -> Result<Option<FinalitySigInfo>, ContractError> {
    FINALITY_SIGNATURES
        .may_load(storage, (height, fp_btc_pk))
        .map_err(|_| ContractError::FailedToLoadFinalitySignature(hex::encode(fp_btc_pk), height))
}

/// Inserts a finality signature into the FINALITY_SIGNATURES map.
/// If a signature already exists for the same height and finality provider, it will be overridden.
pub fn insert_finality_signature(
    storage: &mut dyn Storage,
    height: u64,
    fp_btc_pk: &[u8],
    finality_sig_info: FinalitySigInfo,
) -> StdResult<()> {
    FINALITY_SIGNATURES.save(storage, (height, fp_btc_pk), &finality_sig_info)
}

/// Map of (block height, block hash) tuples to the list of signatories
/// (each identified by the BTC public key in hex) for that block.
const SIGNATORIES_BY_BLOCK_HASH: Map<(u64, &[u8]), HashSet<String>> =
    Map::new("signatories_by_block_hash");

pub fn get_signatories_by_block_hash(
    storage: &dyn Storage,
    height: u64,
    block_hash: &[u8],
) -> Result<Option<HashSet<String>>, ContractError> {
    SIGNATORIES_BY_BLOCK_HASH
        .may_load(storage, (height, block_hash))
        .map_err(|_| ContractError::FailedToLoadSignatories(hex::encode(block_hash), height))
}

/// Inserts a set of signatories into the SIGNATORIES_BY_BLOCK_HASH map.
/// This will override any existing set for the same height and block hash.
pub fn insert_signatories_by_block_hash(
    storage: &mut dyn Storage,
    height: u64,
    block_hash: &[u8],
    signatories: HashSet<String>,
) -> StdResult<()> {
    SIGNATORIES_BY_BLOCK_HASH.save(storage, (height, block_hash), &signatories)
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
/// - If the signatory is already there, return an error.
/// - If the signatory is a new one, the caller is responsible for ensuring that they are
///   inserting the right one. An insertion without a corresponding entry for a finality provider
fn insert_signatory(
    storage: &mut dyn Storage,
    height: u64,
    block_hash: &[u8],
    signatory: &str,
) -> Result<(), ContractError> {
    let mut set = SIGNATORIES_BY_BLOCK_HASH
        .may_load(storage, (height, block_hash))?
        .unwrap_or_else(HashSet::new);
    if !set.insert(signatory.to_string()) {
        return Err(ContractError::DuplicateSignatory(signatory.to_string()));
    }
    insert_signatories_by_block_hash(storage, height, block_hash, set)?;
    Ok(())
}

/// Inserts finality sig and signatory into storage.
/// Returns an error if any of the operations fail.
pub fn insert_finality_sig_and_signatory(
    storage: &mut dyn Storage,
    fp_btc_pk: &[u8],
    height: u64,
    block_hash: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    // Save the finality signature
    // TODO: in the case of an existing finality signature,
    // we are overriding the existing finality signature.
    // https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/44
    let finality_sig_info = FinalitySigInfo {
        finality_sig: signature.to_vec(),
        block_hash: block_hash.to_vec(),
    };
    insert_finality_signature(storage, height, fp_btc_pk, finality_sig_info)?;

    // Add the fp_btc_pk to the signatories for the (height, block_hash) pair
    insert_signatory(storage, height, block_hash, &hex::encode(fp_btc_pk))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::mock_dependencies;

    #[test]
    fn test_insert_finality_sig_and_signatory() {
        let mut deps = mock_dependencies();
        let height = get_random_u64();
        let block_hash = get_random_block_hash();
        let signature = get_random_block_hash();
        let fp_btc_pk = get_random_fp_pk();
        let fp_btc_pk_hex = hex::encode(fp_btc_pk.clone());

        // Insert the data
        insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            height,
            &block_hash,
            &signature,
        )
        .unwrap();

        // Verify finality signature was stored correctly
        let finality_sig_info = get_finality_signature(deps.as_ref().storage, height, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(finality_sig_info.finality_sig, signature);
        assert_eq!(finality_sig_info.block_hash, block_hash);

        // Verify signatory was added to the set
        let signatories = get_signatories_by_block_hash(deps.as_ref().storage, height, &block_hash)
            .unwrap()
            .unwrap();
        assert!(signatories.contains(&fp_btc_pk_hex));
        assert_eq!(signatories.len(), 1);

        // Test case 1 (should fail): duplicate signatory for the same block
        // TODO: replace insert_signatory with insert_signatory_and_finality_sig after
        // resolving #44
        let result = insert_signatory(
            deps.as_mut().storage,
            height,
            &block_hash,
            &fp_btc_pk_hex.clone(),
        );
        assert_eq!(
            result,
            Err(ContractError::DuplicateSignatory(fp_btc_pk_hex.clone()))
        );

        // Test case 2 (should succeed): signing a different block hash at the same height
        let different_block_hash = get_random_block_hash();
        let different_signature = get_random_block_hash();
        let result = insert_finality_sig_and_signatory(
            deps.as_mut().storage,
            &fp_btc_pk,
            height,
            &different_block_hash,
            &different_signature,
        );

        // This should succeed
        assert!(result.is_ok());

        // Verify the new finality signature was stored correctly
        let finality_sig_info = get_finality_signature(deps.as_ref().storage, height, &fp_btc_pk)
            .unwrap()
            .unwrap();
        assert_eq!(finality_sig_info.finality_sig, different_signature);
        assert_eq!(finality_sig_info.block_hash, different_block_hash);

        // Verify signatory was added to the set for the new block hash
        let signatories =
            get_signatories_by_block_hash(deps.as_ref().storage, height, &different_block_hash)
                .unwrap()
                .unwrap();
        assert!(signatories.contains(&fp_btc_pk_hex));
        assert_eq!(signatories.len(), 1);
        // TODO: assert number of finality signatures after resolving #44
    }
}
