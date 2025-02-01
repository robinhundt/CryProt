use bytemuck::{cast_mut, cast_ref, cast_slice, cast_slice_mut};
use rand::{RngCore, SeedableRng};
use seec_core::{aes_rng::AesRng, Block};

// Simple PRNG implementation for the accumulator
pub(crate) struct FastAesRng {
    buffer: Box<[Block; 256]>,
}

impl FastAesRng {
    pub(crate) fn new(seed: Block) -> Self {
        let mut buffer = Box::new([Block::ZERO; 256]);
        let mut aes_rng = AesRng::from_seed(seed);
        aes_rng.fill_bytes(cast_slice_mut(&mut buffer[..]));
        Self { buffer }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        cast_slice(&self.buffer[..])
    }

    pub(crate) fn refill(&mut self) {
        for i in (0..256).step_by(8) {
            let (left, right) = self.buffer.split_at_mut(i);
            let (middle, far_right) = right.split_at_mut(8);

            let b: &mut [Block; 8] = middle.try_into().expect("len is 8");

            let k: &[Block; 8] = if i >= 8 {
                // Use left part when looking backwards
                (&left[i - 8..][..]).try_into().expect("len is 8")
            } else {
                // Use far_right for wrap-around case, taking from the end
                (&far_right[far_right.len() - 8..][..])
                    .try_into()
                    .expect("len is 8")
            };

            aes::hazmat::cipher_round_par(cast_mut(b), cast_ref(k));
        }
    }

    pub fn blocks(&self) -> &[Block; 256] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::FastAesRng;

    #[test]
    fn test_fast_aes_rng() {
        let mut rng = FastAesRng::new(348324_u128.into());
        let old = *rng.blocks();
        rng.refill();
        assert_ne!(&old, rng.blocks());
    }
}
