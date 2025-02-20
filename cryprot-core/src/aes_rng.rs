use std::mem;

use aes::Aes128;
/// RNG based on AES in CTR-like mode.
///
/// This implementation is based on the implementation given in the
/// [scuttlebutt](https://github.com/GaloisInc/swanky/blob/4455754abadee07f168079ac45ef33535b0df27d/scuttlebutt/src/rand_aes.rs)
/// crate. Instead of using an own AES implementation, [`AesRng`](`AesRng`) uses
/// the [aes](`aes`) crate.
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use rand::{CryptoRng, Error, Rng, RngCore, SeedableRng};
use rand_core::block::{BlockRng, BlockRngCore};

use crate::{AES_PAR_BLOCKS, Block};

// TODO i think softspoken ot has some implementation performance optimizations
// see sect 7 https://eprint.iacr.org/2022/192.pdf

/// This uses AES in a counter-mode-esque way, but with the counter always
/// starting at zero. When used as a PRNG this is okay [TODO: citation?].
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl RngCore for AesRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let block_size = mem::size_of::<aes::Block>();
        let block_len = dest.len() / block_size * block_size;
        let (block_bytes, rest_bytes) = dest.split_at_mut(block_len);
        // fast path so we don't unnecessarily copy u32 from BlockRngCore::generate into
        // dest
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(block_bytes);
        for chunk in blocks.chunks_mut(AES_PAR_BLOCKS) {
            for block in chunk.iter_mut() {
                *block = aes::cipher::Array(self.0.core.state.to_ne_bytes());
                self.0.core.state += 1;
            }
            self.0.core.aes.encrypt_blocks(chunk);
        }
        // handle the tail
        self.0.fill_bytes(rest_bytes)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl SeedableRng for AesRng {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::<AesRngCore>::from_seed(seed))
    }

    #[inline]
    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng::<AesRngCore>::from_rng(rng).map(AesRng)
    }
}

impl CryptoRng for AesRng {}

impl AesRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    #[inline]
    pub fn new() -> Self {
        let seed = rand::random::<Block>();
        AesRng::from_seed(seed)
    }

    /// Create a new RNG using a random seed from this one.
    #[inline]
    pub fn fork(&mut self) -> Self {
        let seed = self.r#gen::<Block>();
        AesRng::from_seed(seed)
    }
}

impl Default for AesRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of `AesRng`, used with `BlockRng`.
#[derive(Clone)]
pub struct AesRngCore {
    aes: Aes128,
    state: u128,
}

impl std::fmt::Debug for AesRngCore {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "AesRngCore {{}}")
    }
}

impl BlockRngCore for AesRngCore {
    type Item = u32;
    // This is equivalent to `[Block; 9]`
    type Results = hidden::ParBlockWrapper;

    // Compute `E(state)` nine times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(results.as_mut());
        blocks.iter_mut().for_each(|blk| {
            // aes::Block is a type alias to Array, but type aliases can't be used as
            // constructors
            *blk = aes::cipher::Array(self.state.to_le_bytes());
            self.state += 1;
        });
        self.aes.encrypt_blocks(blocks);
    }
}

mod hidden {
    /// Equivalent to [aes::Block; 9] (which is the parralel block size for the
    /// aes-ni backend). Since size 36 arrays don't impl Default we write a
    /// wrapper.
    #[derive(Copy, Clone)]
    pub struct ParBlockWrapper([u32; 36]);

    impl Default for ParBlockWrapper {
        fn default() -> Self {
            Self([0; 36])
        }
    }

    impl AsMut<[u32]> for ParBlockWrapper {
        fn as_mut(&mut self) -> &mut [u32] {
            &mut self.0
        }
    }

    impl AsRef<[u32]> for ParBlockWrapper {
        fn as_ref(&self) -> &[u32] {
            &self.0
        }
    }
}

impl SeedableRng for AesRngCore {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = Aes128::new(&seed.into());
        AesRngCore {
            aes,
            state: Default::default(),
        }
    }
}

impl CryptoRng for AesRngCore {}

impl From<AesRngCore> for AesRng {
    #[inline]
    fn from(core: AesRngCore) -> Self {
        AesRng(BlockRng::new(core))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let mut rng = AesRng::new();
        let a = rng.r#gen::<[Block; 8]>();
        let b = rng.r#gen::<[Block; 8]>();
        assert_ne!(a, b);
    }
}
