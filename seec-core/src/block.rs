use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

use aes::cipher::{self, array::sizes};
use bytemuck::{Pod, Zeroable};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use wide::u8x16;

use crate::random_oracle::RandomOracle;

/// A 128-bit block. Uses SIMD operations where available.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Pod, Zeroable)]
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

    ///  Create a block from 128 [`Choice`]s.
    ///
    /// # Panics
    /// If choices.len() != 128
    #[inline]
    pub fn from_choices(choices: &[Choice]) -> Self {
        assert_eq!(128, choices.len(), "choices.len() must be 128");
        let mut bytes = [0_u8; 16];
        for (chunk, byte) in choices.chunks_exact(8).zip(&mut bytes) {
            for (i, choice) in chunk.iter().enumerate() {
                *byte ^= choice.unwrap_u8() << i;
            }
        }
        Self::new(bytes)
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

impl BitAndAssign for Block {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOr for Block {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Block {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
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

impl AsMut<[u8]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl From<Block> for cipher::Array<u8, sizes::U16> {
    #[inline]
    fn from(value: Block) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<cipher::Array<u8, sizes::U16>> for Block {
    #[inline]
    fn from(value: cipher::Array<u8, sizes::U16>) -> Self {
        Self::new(value.0)
    }
}
