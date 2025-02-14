pub type RandomOracle = blake3::Hasher;
pub type Hash = blake3::Hash;


pub fn hash(input: &[u8]) -> Hash {
    blake3::hash(input)
}