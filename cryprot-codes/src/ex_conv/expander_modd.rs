use std::mem::{self};

use bytemuck::{cast_slice, cast_slice_mut};
use cryprot_core::{Block, utils::log2_ceil};
use fastdivide::DividerU64;

use super::fast_aes_rng::FastAesRng;

const RAND_BLOCKS: usize = 256;
const RAND_U64_VALS: usize = RAND_BLOCKS * Block::BYTES / mem::size_of::<u64>();

pub(crate) struct ExpanderModd {
    rng: FastAesRng,
    mod_val: u64,
    idx: usize,
    vals: Box<[Block; RAND_BLOCKS]>,
    mod_divider: DividerU64,
    m_is_pow2: bool,
    m_pow2_mask: u64,
    m_pow2_mask_blk: Block,
}

impl ExpanderModd {
    pub(crate) fn new(seed: Block, m: u64) -> Self {
        let vals = Box::new([Block::ZERO; RAND_BLOCKS]);
        let mut expander = ExpanderModd {
            rng: FastAesRng::new(seed),
            mod_val: 0,
            idx: 0,
            vals,
            mod_divider: DividerU64::divide_by(1), // Dummy initial value
            m_is_pow2: false,
            m_pow2_mask: 0,
            m_pow2_mask_blk: Block::ZERO,
        };
        expander.init(seed, m);
        expander
    }

    pub(crate) fn init(&mut self, seed: Block, m: u64) {
        self.rng = FastAesRng::new(seed);
        self.mod_val = m;
        self.mod_divider = DividerU64::divide_by(m);
        let m_pow2 = log2_ceil(self.mod_val as usize) as u32;
        self.m_is_pow2 = m_pow2 == self.mod_val.ilog2();
        if self.m_is_pow2 {
            self.m_pow2_mask = self.mod_val - 1;
            self.m_pow2_mask_blk = Block::from([self.m_pow2_mask, self.m_pow2_mask]);
        }
        self.refill();
    }

    #[inline(always)]
    pub(crate) fn get(&mut self) -> usize {
        // RAND_U64_VALS is equal to len of vals: &[u64]
        if self.idx == RAND_U64_VALS {
            self.refill();
        }
        let vals: &[u64] = cast_slice(&self.vals[..]);
        // SAFETY: self.idx is always < RAND_U64_VALS == vals.len(). If self.idx ==
        // RAND_U64_VALS, it is set to to 0 in self.refill()
        let val = unsafe { *vals.get_unchecked(self.idx) };
        self.idx += 1;
        val as usize
    }

    fn refill(&mut self) {
        self.idx = 0;

        self.rng.refill();

        let src = self.rng.blocks();
        let dest: &mut [Block] = &mut self.vals[..];
        if self.m_is_pow2 {
            for (dest, src) in dest.iter_mut().zip(src) {
                *dest = *src & self.m_pow2_mask_blk;
            }
        } else {
            dest.copy_from_slice(src);
            let vals: &mut [u64] = cast_slice_mut(&mut self.vals[..]);
            for chunk in vals.chunks_mut(32) {
                Self::do_mod32(chunk, &self.mod_divider, self.mod_val);
            }
        }
    }

    #[inline]
    fn do_mod32(vals: &mut [u64], divider: &DividerU64, mod_val: u64) {
        for val in vals {
            let quotient = divider.divide(*val);
            *val -= quotient * mod_val;
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_expander_modd() {
        let seed = StdRng::seed_from_u64(3454).random();
        let m = 100;
        let mut expander = ExpanderModd::new(seed, m as u64);

        for _ in 0..1000 {
            let val = expander.get();
            assert!(val < m);
        }
    }

    #[test]
    fn test_expander_modd_pow2() {
        let seed = StdRng::seed_from_u64(3454).random();
        let m = 128; // Power of 2
        let mut expander = ExpanderModd::new(seed, m as u64);

        for _ in 0..1000 {
            let val = expander.get();
            assert!(val < m);
        }
    }
}
