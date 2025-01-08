use std::ops::{BitAnd, BitOr, BitXor, Not};

use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};
use wide::u8x16;

use crate::random_oracle::RandomOracle;

/// A 128-bit block. Uses SIMD operations where available.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Block(u8x16);

impl Block {
    pub const ZERO: Self = Self(u8x16::ZERO);
    pub const ONES: Self = Self(u8x16::MAX);

    #[inline]
    pub const fn new(bits: [u8; 16]) -> Self {
        Self(u8x16::new(bits))
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_array_ref()
    }

    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 16] {
        self.0.as_array_mut()
    }

    #[inline]
    pub fn ro_hash(&self) -> blake3::Hash {
        let mut ro = RandomOracle::new();
        ro.update(self.as_bytes());
        ro.finalize()
    }
}

// Implement standard operators for more ergonomic usage
impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for Block {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Not for Block {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_array_ref() == other.0.as_array_ref()
    }
}

impl Eq for Block {}

impl Distribution<Block> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let bits = rng.gen();
        Block::new(bits)
    }
}
