//! RNG based on AES in CTR mode.
//!
//! This implementation is based on the implementation given in the
//! [scuttlebutt](https://github.com/GaloisInc/swanky/blob/4455754abadee07f168079ac45ef33535b0df27d/scuttlebutt/src/rand_aes.rs)
//! crate. Instead of using an own AES implementation, [`AesRng`](`AesRng`) uses
//! the [aes](`aes`) crate.
//!
//! On platforms wwith hardware accelerated AES instructions, the [`AesRng`] can
//! generate multiple GiB of random data per second. Make sure to compile with
//! the `aes` target feature enabled to have optimal performance without runtime
//! detection of the feature.
use std::mem;

use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use rand::{RngExt, SeedableRng};
use rand_core::{
    TryCryptoRng, TryRng,
    block::{BlockRng, Generator},
};

use crate::{AES_PAR_BLOCKS, Block};

// TODO i think softspoken ot has some implementation performance optimizations
// see sect 7 https://eprint.iacr.org/2022/192.pdf

/// This uses AES in a counter-mode to implement a PRG. TODO: Citation for
/// why/when this is secure.
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl TryRng for AesRng {
    type Error = core::convert::Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_word())
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64_from_u32())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let block_size = mem::size_of::<aes::Block>();
        let block_len = dest.len() / block_size * block_size;
        let (block_bytes, rest_bytes) = dest.split_at_mut(block_len);
        // fast path so we don't unnecessarily copy u32 from Generator::generate into
        // dest
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(block_bytes);
        for chunk in blocks.chunks_mut(AES_PAR_BLOCKS) {
            for block in chunk.iter_mut() {
                *block = aes::cipher::Array(self.0.core.state.to_le_bytes());
                self.0.core.state += 1;
            }
            self.0.core.aes.encrypt_blocks(chunk);
        }
        // handle the tail
        self.0.fill_bytes(rest_bytes);
        Ok(())
    }
}

impl SeedableRng for AesRng {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::new(AesRngCore::from_seed(seed)))
    }
}

impl TryCryptoRng for AesRng {}

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
        let seed = self.random::<Block>();
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

impl Generator for AesRngCore {
    // This is equivalent to `[aes::Block; AES_PAR_BLOCKS]`
    type Output = [u32; AES_PAR_BLOCKS * (mem::size_of::<aes::Block>() / mem::size_of::<u32>())];

    // Compute `E(state)` AES_PAR_BLOCKS times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Output) {
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(results);
        blocks.iter_mut().for_each(|blk| {
            // aes::Block is a type alias to Array, but type aliases can't be used as
            // constructors
            *blk = aes::cipher::Array(self.state.to_le_bytes());
            self.state += 1;
        });
        self.aes.encrypt_blocks(blocks);
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
        let a = rng.random::<[Block; 8]>();
        let b = rng.random::<[Block; 8]>();
        assert_ne!(a, b);
    }
}
