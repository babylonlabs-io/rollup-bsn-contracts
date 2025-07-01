use cosmwasm_schema::cw_serde;
use cw_storage_plus::Map;
use std::collections::HashSet;

use crate::state::Bytes;

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

/// Map of signatures by block height and fp
pub(crate) const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of block hashes by block height and fp
pub(crate) const BLOCK_HASHES: Map<(u64, &str), Vec<u8>> = Map::new("block_hashes");

/// Map of (block height, block hash) tuples to the list of fps that voted for this combination
pub(crate) const BLOCK_VOTES: Map<(u64, &[u8]), HashSet<String>> = Map::new("block_votes");

/// Map of evidence by block height and fp
pub(crate) const EVIDENCES: Map<(u64, &str), Evidence> = Map::new("evidences");
