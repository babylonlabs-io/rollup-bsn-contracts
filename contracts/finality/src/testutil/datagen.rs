use crate::state::finality::FinalitySigInfo;
use rand::{rng, Rng};

pub fn get_random_block_hash() -> Vec<u8> {
    let mut rng = rng();
    (0..32).map(|_| rng.random()).collect()
}

pub fn get_random_fp_pk_hex() -> String {
    let mut rng = rng();
    let bytes: Vec<u8> = (0..33).map(|_| rng.random()).collect();
    hex::encode(bytes)
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
