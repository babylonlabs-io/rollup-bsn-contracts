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

pub fn get_random_string() -> String {
    let mut rng = rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        .chars()
        .collect();
    let len = rng.random_range(1..=20);
    (0..len)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

pub fn get_random_bool() -> bool {
    let mut rng = rng();
    rng.random()
}

pub fn get_random_u64_range(start: u64, end: u64) -> u64 {
    let mut rng = rng();
    rng.random_range(start..=end)
}
