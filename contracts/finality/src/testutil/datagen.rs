use crate::state::{evidence::Evidence, finality::FinalitySigInfo};
use rand::{rng, Rng};

pub fn get_random_u64() -> u64 {
    let mut rng = rng();
    rng.random_range(1..=1000)
}

pub fn get_random_block_hash() -> Vec<u8> {
    let mut rng = rng();
    (0..32).map(|_| rng.random()).collect()
}

pub fn get_random_fp_pk() -> Vec<u8> {
    let mut rng = rng();
    (0..33).map(|_| rng.random()).collect()
}

pub fn get_random_fp_pk_hex() -> String {
    hex::encode(get_random_fp_pk())
}

pub fn get_random_pub_rand() -> Vec<u8> {
    let mut rng = rng();
    (0..32).map(|_| rng.random()).collect()
}

pub fn get_random_finality_sig(block_hash: &[u8]) -> FinalitySigInfo {
    let mut rng = rng();
    FinalitySigInfo {
        finality_sig: (0..64).map(|_| rng.random()).collect(),
        block_hash: block_hash.to_vec(),
    }
}

/// Get a random evidence for a given height and finality provider.
/// We are adding it here instead of datagen.rs as it is only used here.
/// NOTE: The result is a mocked result, the signatures are not valid.
pub fn get_random_evidence(height: u64, fp_btc_pk: &[u8]) -> Evidence {
    Evidence {
        fp_btc_pk: fp_btc_pk.to_vec(),
        block_height: height,
        pub_rand: get_random_pub_rand(),
        canonical_app_hash: get_random_block_hash(),
        fork_app_hash: get_random_block_hash(),
        canonical_finality_sig: (0..64).map(|_| rand::random()).collect(),
        fork_finality_sig: (0..64).map(|_| rand::random()).collect(),
    }
}
