use crate::state::finality::FinalitySigInfo;
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
