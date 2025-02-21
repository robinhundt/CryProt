use std::{
    fmt,
    ops::{Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr},
};

use aes::cipher::{self, array::sizes};
use bytemuck::{Pod, Zeroable};
use rand::{Rng, distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use wide::u8x16;

use crate::random_oracle::RandomOracle;

pub mod gf128;

/// A 128-bit block. Uses SIMD operations where available.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Pod, Zeroable)]
#[repr(transparent)]
pub struct Block(u8x16);

impl Block {
    pub const ZERO: Self = Self(u8x16::ZERO);
    pub const ONES: Self = Self(u8x16::MAX);
    pub const ONE: Self = Self::new(1_u128.to_ne_bytes());
    pub const MASK_LSB: Self = Self::pack(u64::MAX << 1, u64::MAX);

    pub const BYTES: usize = 16;
    pub const BITS: usize = 128;

    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(u8x16::new(bytes))
    }

    #[inline]
    pub const fn splat(byte: u8) -> Self {
        Self::new([byte; 16])
    }

    #[inline]
    pub const fn pack(low: u64, high: u64) -> Self {
        let mut bytes = [0; 16];
        let low = low.to_ne_bytes();
        let mut i = 0;
        while i < low.len() {
            bytes[i] = low[i];
            i += 1;
        }

        let high = high.to_ne_bytes();
        let mut i = 0;
        while i < high.len() {
            bytes[i + 8] = high[i];
            i += 1;
        }

        Self::new(bytes)
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

    #[inline]
    pub fn low(&self) -> u64 {
        u64::from_ne_bytes(self.as_bytes()[..8].try_into().expect("correct len"))
    }

    #[inline]
    pub fn high(&self) -> u64 {
        u64::from_ne_bytes(self.as_bytes()[8..].try_into().expect("correct len"))
    }

    #[inline]
    pub fn lsb(&self) -> bool {
        *self & Block::ONE == Block::ONE
    }

    #[inline]
    pub fn bits(&self) -> impl Iterator<Item = bool> {
        struct BitIter {
            blk: Block,
            idx: usize,
        }
        impl Iterator for BitIter {
            type Item = bool;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                if self.idx < Block::BITS {
                    self.idx += 1;
                    let bit = (self.blk >> (self.idx - 1)) & Block::ONE != Block::ZERO;
                    Some(bit)
                } else {
                    None
                }
            }
        }
        BitIter { blk: *self, idx: 0 }
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

impl<Rhs> Shl<Rhs> for Block
where
    u128: Shl<Rhs, Output = u128>,
{
    type Output = Block;

    #[inline]
    fn shl(self, rhs: Rhs) -> Self::Output {
        Self::from(u128::from(self) << rhs)
    }
}

impl<Rhs> Shr<Rhs> for Block
where
    u128: Shr<Rhs, Output = u128>,
{
    type Output = Block;

    #[inline]
    fn shr(self, rhs: Rhs) -> Self::Output {
        Self::from(u128::from(self) >> rhs)
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
        let a: u128 = (*self).into();
        let b: u128 = (*other).into();
        a.ct_eq(&b).into()
    }
}

impl Eq for Block {}

impl Distribution<Block> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        Block::new(bytes)
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
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

impl From<[u64; 2]> for Block {
    #[inline]
    fn from(value: [u64; 2]) -> Self {
        bytemuck::cast(value)
    }
}

impl From<Block> for [u64; 2] {
    #[inline]
    fn from(value: Block) -> Self {
        bytemuck::cast(value)
    }
}

impl From<Block> for u128 {
    #[inline]
    fn from(value: Block) -> Self {
        // todo correct endianness?
        u128::from_ne_bytes(*value.as_bytes())
    }
}

impl From<&Block> for u128 {
    #[inline]
    fn from(value: &Block) -> Self {
        // todo correct endianness?
        u128::from_ne_bytes(*value.as_bytes())
    }
}

impl From<usize> for Block {
    fn from(value: usize) -> Self {
        (value as u128).into()
    }
}

impl From<u128> for Block {
    #[inline]
    fn from(value: u128) -> Self {
        Self::new(value.to_ne_bytes())
    }
}

impl From<&u128> for Block {
    #[inline]
    fn from(value: &u128) -> Self {
        Self::new(value.to_ne_bytes())
    }
}

#[cfg(target_arch = "x86_64")]
impl From<std::arch::x86_64::__m128i> for Block {
    #[inline]
    fn from(value: std::arch::x86_64::__m128i) -> Self {
        bytemuck::cast(value)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<&std::arch::x86_64::__m128i> for Block {
    #[inline]
    fn from(value: &std::arch::x86_64::__m128i) -> Self {
        bytemuck::cast(*value)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<Block> for std::arch::x86_64::__m128i {
    #[inline]
    fn from(value: Block) -> Self {
        bytemuck::cast(value)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<&Block> for std::arch::x86_64::__m128i {
    #[inline]
    fn from(value: &Block) -> Self {
        bytemuck::cast(*value)
    }
}

impl ConditionallySelectable for Block {
    #[inline]
    // adapted from https://github.com/dalek-cryptography/subtle/blob/369e7463e85921377a5f2df80aabcbbc6d57a930/src/lib.rs#L510-L517
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // if choice = 0, mask = (-0) = 0000...0000
        // if choice = 1, mask = (-1) = 1111...1111
        let mask = Block::new((-(choice.unwrap_u8() as i128)).to_le_bytes());
        *a ^ (mask & (*a ^ *b))
    }
}

impl Add for Block {
    type Output = Block;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        // todo is this a sensible implementation?
        let a: u128 = self.into();
        let b: u128 = rhs.into();
        Self::from(a.wrapping_add(b))
    }
}

impl fmt::Binary for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&u128::from(*self), f)
    }
}

#[cfg(feature = "num-traits")]
impl num_traits::Zero for Block {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

#[cfg(test)]
mod tests {
    use subtle::{Choice, ConditionallySelectable};

    use crate::Block;

    #[test]
    fn test_block_cond_select() {
        let choice = Choice::from(0);
        assert_eq!(
            Block::ZERO,
            Block::conditional_select(&Block::ZERO, &Block::ONES, choice)
        );
        let choice = Choice::from(1);
        assert_eq!(
            Block::ONES,
            Block::conditional_select(&Block::ZERO, &Block::ONES, choice)
        );
    }

    #[test]
    fn test_block_low_high() {
        let b = Block::from(1_u128);
        assert_eq!(1, b.low());
        assert_eq!(0, b.high());
    }

    #[test]
    fn test_from_into_u64_arr() {
        let b = Block::from([42, 65]);
        assert_eq!(42, b.low());
        assert_eq!(65, b.high());
        assert_eq!([42, 65], <[u64; 2]>::from(b));
    }

    #[test]
    fn test_pack() {
        let b = Block::pack(42, 123);
        assert_eq!(42, b.low());
        assert_eq!(123, b.high());
    }

    #[test]
    fn test_mask_lsb() {
        assert_eq!(Block::ONES ^ Block::ONE, Block::MASK_LSB);
    }

    #[test]
    fn test_bits() {
        let b: Block = 0b101_u128.into();
        let mut iter = b.bits();
        assert_eq!(Some(true), iter.next());
        assert_eq!(Some(false), iter.next());
        assert_eq!(Some(true), iter.next());
        for rest in iter {
            assert_eq!(false, rest);
        }
    }
}
