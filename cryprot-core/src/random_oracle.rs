//! Aliases to Blake3 as a random oracle.

pub type RandomOracle = blake3::Hasher;
pub type Hash = blake3::Hash;

/// Hash the input bytes using a random oracle.
pub fn hash(input: &[u8]) -> Hash {
    blake3::hash(input)
}
