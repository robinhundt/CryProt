use std::ops::{
    Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr,
};

use aes::cipher::{self, array::sizes};
use bytemuck::{Pod, Zeroable};
use rand::{distributions::Standard, prelude::Distribution, Fill, Rng};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use wide::u8x16;

use crate::random_oracle::RandomOracle;

/// A 128-bit block. Uses SIMD operations where available.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Pod, Zeroable)]
#[repr(transparent)]
pub struct Block(u8x16);

impl Block {
    pub const ZERO: Self = Self(u8x16::ZERO);
    pub const ONES: Self = Self(u8x16::MAX);
    pub const ONE: Self = Self::new(1_u128.to_ne_bytes());

    pub const BYTES: usize = 16;
    pub const BITS: usize = 128;

    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(u8x16::new(bytes))
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

impl Distribution<Block> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let bits = rng.gen();
        Block::new(bits)
    }
}

impl Fill for Block {
    fn try_fill<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
        *self = rng.gen();
        Ok(())
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
impl From<Block> for std::arch::x86_64::__m128i {
    #[inline]
    fn from(value: Block) -> Self {
        bytemuck::cast(value)
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

#[cfg(feature = "num-traits")]
impl num_traits::Zero for Block {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

mod gf128 {
    use super::Block;

    impl Block {
        pub fn gf128_mul(&self, rhs: Block) -> Block {
            // Adapted from [polyval-rs](https://github.com/ericlagergren/polyval-rs/blob/f977ed940968f1c26f8b30520c9682597b96e05a/src/backend/generic.rs)
            // We perform schoolbook multiplication of x and y:
            //
            // (x1,x0)*(y1,y0) = (x1*y1) + (x1*y0 + x0*y1) + (x0*y0)
            //                      H         M       M         L
            //
            // The middle result (M) can be simplified with Karatsuba
            // multiplication:
            //
            // (x1*y0 + x0*y1) = (x1+x0) * (y1+x0) + (x1*y1) + (x0*y0)
            //        M                                 H         L
            //
            // This requires one less 64-bit multiplication and reuses
            // the existing results H and L. (H and L are added to M in
            // the montgomery reduction; see x1 and x2.)
            //
            // This gives us a 256-bit product, X.
            //
            // Use the "Shift-XOR reflected reduction" method to reduce
            // it modulo x^128 + x^127 + x^126 + x^121 + 1.
            //
            // This is faster than Gueron's "Fast reduction ..." method
            // without CMUL/PMULL intrinsics.
            //
            // See [gueron] page 17-19.
            //
            // [gueron]: https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf]
            let x0 = self.low();
            let x1 = self.high();
            let y0 = rhs.low();
            let y1 = rhs.high();

            let h_block = gf128_mul(x1, y1); // H
            let m_block = gf128_mul(x1 ^ x0, y1 ^ y0); // M
            let l_block = gf128_mul(x0, y0); // L

            let mut h0 = h_block.low();
            let mut h1 = h_block.high();
            let mut m0 = m_block.low();
            let mut m1 = m_block.high();
            let l0 = l_block.low();
            let mut l1 = l_block.high();

            m0 ^= l0 ^ h0;
            m1 ^= l1 ^ h1;

            l1 ^= m0 ^ (l0 << 63) ^ (l0 << 62) ^ (l0 << 57);
            h0 ^= l0 ^ (l0 >> 1) ^ (l0 >> 2) ^ (l0 >> 7);
            h0 ^= m1 ^ (l1 << 63) ^ (l1 << 62) ^ (l1 << 57);
            h1 ^= l1 ^ (l1 >> 1) ^ (l1 >> 2) ^ (l1 >> 7);

            Block::from([h0, h1])
        }
    }

    fn gf128_mul(x: u64, y: u64) -> Block {
        Block::from((x as u128) * (y as u128))
        // const MASK0: u128 = 0x21084210842108421084210842108421;
        // const MASK1: u128 = 0x42108421084210842108421084210842;
        // const MASK2: u128 = 0x84210842108421084210842108421084;
        // const MASK3: u128 = 0x08421084210842108421084210842108;
        // const MASK4: u128 = 0x10842108421084210842108421084210;

        // // Split both x and y into 5 words with four-bit holes.
        // let x0 = (x as u128) & MASK0;
        // let y0 = (y as u128) & MASK0;
        // let x1 = (x as u128) & MASK1;
        // let y1 = (y as u128) & MASK1;
        // let x2 = (x as u128) & MASK2;
        // let y2 = (y as u128) & MASK2;
        // let x3 = (x as u128) & MASK3;
        // let y3 = (y as u128) & MASK3;
        // let x4 = (x as u128) & MASK4;
        // let y4 = (y as u128) & MASK4;

        // let t0 = (x0 * y0) ^ (x1 * y4) ^ (x2 * y3) ^ (x3 * y2) ^ (x4 * y1);
        // let t1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y4) ^ (x3 * y3) ^ (x4 * y2);
        // let t2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y4) ^ (x4 * y3);
        // let t3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0) ^ (x4 * y4);
        // let t4 = (x0 * y4) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1) ^ (x4 * y0);

        // Block::from((t0 & MASK0) | (t1 & MASK1) | (t2 & MASK2) | (t3 & MASK3)
        // | (t4 & MASK4))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NZ_BLOCK: Block = Block::new(12345_u128.to_ne_bytes());

        #[test]
        fn test_gf128_mul_zero() {
            assert_eq!(Block::ZERO.gf128_mul(12345.into()), Block::ZERO);
            assert_eq!(Block::from(12345).gf128_mul(Block::ZERO), Block::ZERO);
            assert_eq!(Block::ZERO.gf128_mul(Block::ZERO), Block::ZERO);
        }

        #[test]
        fn test_gf128_mul_one() {
            assert_eq!(Block::ONE.gf128_mul(NZ_BLOCK), NZ_BLOCK);
            assert_eq!(NZ_BLOCK.gf128_mul(Block::ONE), NZ_BLOCK);
            assert_eq!(Block::ONE.gf128_mul(Block::ONE), Block::ONE);
        }

        // #[test]
        // fn test_gf128_mul_example1() {
        //     // Example from Wikipedia (slightly modified for 128-bit)
        //     let a: Block = 0x80000000000000000000000000000000.into(); // x^127
        //     let b: Block = 0x00000000000000000000000000000087.into(); // x^7 + x^2 +
        // x + 1

        //     let expected: Block =
        //         ((1u128 << 127) | (1u128 << 13) | (1u128 << 6) | (1u128 << 3) |
        // 1).into();     let result = a.gf128_mul(b);
        //     assert_eq!(result, expected);
        // }

        #[test]
        fn test_gf128_mul_random() {
            // Just a basic test to see if it runs without panicking for random inputs
            use rand::Rng;
            let mut rng = rand::thread_rng();
            for _ in 0..1000 {
                let a: Block = rng.gen();
                let b: Block = rng.gen();
                a.gf128_mul(b); // Just check it doesn't crash
            }
        }
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
}
