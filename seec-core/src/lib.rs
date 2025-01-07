use std::ops::{BitAnd, BitOr, BitXor, Not};

use rand::{distributions::Standard, prelude::Distribution, Rng};
use wide::u64x2;

/// A 128-bit block. Uses SIMD operations where available.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Block(u64x2);

impl Block {
    pub const ZERO: Self = Self(u64x2::ZERO);
    pub const ONES: Self = Self::new([u64::MAX, u64::MAX]);

    pub const fn new(bits: [u64; 2]) -> Self {
        Self(u64x2::new(bits))
    }
}

// Implement standard operators for more ergonomic usage
impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
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

impl Distribution<Block> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let bits = rng.gen();
        Block::new(bits)
    }
}
