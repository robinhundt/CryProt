use std::mem;

use bytemuck::{cast, cast_slice_mut};
use cryprot_core::block::Block;
use expander::ExpanderCode;
use fast_aes_rng::FastAesRng;
use seq_macro::seq;

use crate::Coeff;

mod expander;
mod expander_modd;
mod fast_aes_rng;

#[derive(Debug, Clone, Copy)]
pub struct ExConvCode {
    expander: ExpanderCode,
    conf: ExConvCodeConfig,
    message_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ExConvCodeConfig {
    pub seed: Block,
    pub code_size: usize,
    pub accumulator_size: usize,
    pub acc_twice: bool,
    pub regular_expander: bool,
    pub expander_weight: usize,
}

impl Default for ExConvCodeConfig {
    fn default() -> Self {
        Self {
            seed: [56756745976768754, 9996754675674599].into(),
            code_size: 0,
            accumulator_size: 24,
            acc_twice: true,
            regular_expander: true,
            expander_weight: 7,
        }
    }
}

const CC_BLOCK: Block = Block::new([0xcc; 16]);

impl ExConvCode {
    pub fn new(message_size: usize) -> Self {
        Self::new_with_conf(message_size, ExConvCodeConfig::default())
    }

    pub fn new_with_conf(message_size: usize, mut conf: ExConvCodeConfig) -> Self {
        if conf.code_size == 0 {
            conf.code_size = 2 * message_size;
        }
        let expander = ExpanderCode::new(
            conf.code_size - message_size,
            conf.expander_weight,
            conf.regular_expander,
            conf.seed ^ CC_BLOCK,
        );
        Self {
            expander,
            message_size,
            conf,
        }
    }

    pub fn parity_rows(&self) -> usize {
        self.conf.code_size - self.message_size
    }

    pub fn parity_cols(&self) -> usize {
        self.conf.code_size
    }

    pub fn generator_rows(&self) -> usize {
        self.message_size
    }

    pub fn generator_cols(&self) -> usize {
        self.conf.code_size
    }

    pub fn message_size(&self) -> usize {
        self.message_size
    }

    pub fn conf(&self) -> &ExConvCodeConfig {
        &self.conf
    }

    pub fn dual_encode<T: Coeff>(&self, e: &mut [T]) {
        assert_eq!(self.conf.code_size, e.len(), "e must have len of code_size");
        let (prefix, suffix) = e.split_at_mut(self.message_size);
        self.accumulate(suffix);
        self.expander.expand(suffix, prefix);
    }

    fn accumulate<T: Coeff>(&self, x: &mut [T]) {
        let size = self.conf.code_size - self.message_size;
        debug_assert_eq!(size, x.len());

        self.accumulate_fixed(x, self.conf.seed);
        if self.conf.acc_twice {
            self.accumulate_fixed(x, !self.conf.seed);
        }
    }

    fn accumulate_fixed<T: Coeff>(&self, x: &mut [T], seed: Block) {
        let mut rng = FastAesRng::new(seed);
        let mut mtx_coeffs = rng.bytes();

        let main = x.len() - 1 - self.conf.accumulator_size;
        for i in 0..x.len() {
            if mtx_coeffs.len() < self.conf.accumulator_size.div_ceil(8) {
                rng.refill();
                mtx_coeffs = rng.bytes();
            }

            if i < main {
                self.acc_one_gen::<false, _>(x, i, mtx_coeffs);
            } else {
                self.acc_one_gen::<true, _>(x, i, mtx_coeffs);
            }
            mtx_coeffs = &mtx_coeffs[1..];
        }
    }

    fn acc_one_gen<const RANGE_CHECK: bool, T: Coeff>(
        &self,
        x: &mut [T],
        i: usize,
        matrix_coeffs: &[u8],
    ) {
        let mut matrix_coeffs = matrix_coeffs.iter().copied();
        let size = x.len();
        let xi = x[i];
        let mut j = i + 1;
        if RANGE_CHECK && j >= size {
            j -= size;
        }

        let mut k = 0;
        while k + 7 < self.conf.accumulator_size {
            let b = matrix_coeffs.next().expect("insufficient coeffs");
            Self::acc_one_8::<RANGE_CHECK, _>(x, xi, j, b);

            j += 8;
            if RANGE_CHECK && j >= size {
                j -= size;
            }
            k += 8;
        }

        while k < self.conf.accumulator_size {
            let mut b = matrix_coeffs.next().expect("insufficient coeffs");
            let mut p = 0;
            while p < 8 && k < self.conf.accumulator_size {
                if b & 1 != 0 {
                    x[j] ^= xi;
                }
                p += 1;
                k += 1;
                b >>= 1;
                j += 1;
                if RANGE_CHECK && j >= size {
                    j -= size;
                }
            }
            k += 1;
        }

        x[j] ^= xi;
    }

    #[inline(always)]
    fn acc_one_8_offsets<const RANGE_CHECK: bool, T: Coeff>(x: &mut [T], j: usize) -> [usize; 8] {
        let size = x.len();
        let mut js = [j, j + 1, j + 2, j + 3, j + 4, j + 5, j + 6, j + 7];
        if !RANGE_CHECK {
            debug_assert!(js[7] < x.len());
        }

        if RANGE_CHECK {
            for j in js.iter_mut() {
                if *j >= size {
                    *j -= size;
                }
            }
        }
        js
    }

    fn acc_one_8<const RANGE_CHECK: bool, T: Coeff>(x: &mut [T], xi: T, j: usize, b: u8) {
        if mem::size_of::<T>() == 16 && mem::align_of::<T>() == 16 {
            #[cfg(target_feature = "sse4.1")]
            Self::acc_one_8_sse::<RANGE_CHECK>(cast_slice_mut(x), cast(xi), j, b);
            #[cfg(not(target_feature = "sse4.1"))]
            Self::acc_one_8_scalar::<RANGE_CHECK, _>(x, xi, j, b);
        } else {
            Self::acc_one_8_scalar::<RANGE_CHECK, _>(x, xi, j, b);
        }
    }

    fn acc_one_8_scalar<const RANGE_CHECK: bool, T: Coeff>(x: &mut [T], xi: T, j: usize, b: u8) {
        let js = Self::acc_one_8_offsets::<RANGE_CHECK, _>(x, j);

        let b_bits = [b & 1, b & 2, b & 4, b & 8, b & 16, b & 32, b & 64, b & 128];

        // I've tried replacing these index operations with unchecked ones, but there is
        // no measurable performance boost
        seq!(N in 0..8 {
            if b_bits[N] != 0 {
                x[js[N]] ^= xi;
            }
        });
    }

    #[cfg(target_feature = "sse4.1")]
    #[inline(always)]
    pub fn acc_one_8_sse<const RANGE_CHECK: bool>(x: &mut [Block], xi: Block, j: usize, b: u8) {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        let js = Self::acc_one_8_offsets::<RANGE_CHECK, _>(x, j);
        let rnd: __m128i = Block::splat(b).into();
        // SAFETY: sse4.1 is available per cfg
        let bb = unsafe {
            let bshift = [
                _mm_slli_epi32::<7>(rnd),
                _mm_slli_epi32::<6>(rnd),
                _mm_slli_epi32::<5>(rnd),
                _mm_slli_epi32::<4>(rnd),
                _mm_slli_epi32::<3>(rnd),
                _mm_slli_epi32::<2>(rnd),
                _mm_slli_epi32::<1>(rnd),
                rnd,
            ];
            let xii: __m128 = bytemuck::cast(xi);
            let zero = _mm_setzero_ps();
            let mut bb: [__m128; 8] = bytemuck::cast(bshift);

            seq!(N in 0..8 {
                bb[N] = _mm_blendv_ps(zero, xii, bb[N]);
            });
            bb
        };

        #[cfg(debug_assertions)]
        for (i, bb) in bb.iter().enumerate() {
            let exp = if ((b >> i) & 1) != 0 { xi } else { Block::ZERO };
            debug_assert_eq!(exp, bytemuck::cast(*bb))
        }

        seq!(N in 0..8 {
            // SAFETY: if j < x.len() - 8, js returned by acc_one_8_offsets are always < x.len()
            // if x.len() - 8 < j < x.len(), we are called with RANGE_CHECK true and the js are wrapped around
            *unsafe { x.get_unchecked_mut(js[N]) } ^= bytemuck::cast(bb[N]);
        });
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "libote-compat")]
    use bytemuck::cast_slice_mut;
    use cryprot_core::block::Block;
    #[cfg(feature = "libote-compat")]
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::*;

    // Helper function to create a Block from a u8 array
    fn create_block(value: u8) -> Block {
        Block::new([value; 16])
    }

    #[test]
    fn test_config_with_explicit_code_size() {
        let message_size = 100;
        let code_size = 250;
        let expander_weight = 5;
        let accumulator_size = 24;
        let seed = create_block(0xAA);
        let code = ExConvCode::new_with_conf(
            message_size,
            ExConvCodeConfig {
                seed,
                code_size,
                accumulator_size,
                expander_weight,
                ..Default::default()
            },
        );

        assert_eq!(code.message_size, message_size);
        assert_eq!(code.conf.code_size, code_size);
        assert_eq!(code.conf.accumulator_size, accumulator_size);
        assert_eq!(code.conf.seed, seed);
    }

    #[test]
    fn test_config_with_default_code_size() {
        let message_size = 100;
        let code = ExConvCode::new(message_size);
        assert_eq!(code.conf.code_size, 2 * message_size);
    }

    #[test]
    fn test_generator_dimensions() {
        let message_size = 100;
        let code = ExConvCode::new(message_size);
        let code_size = code.conf.code_size;

        assert_eq!(code.generator_rows(), message_size);
        assert_eq!(code.generator_cols(), code_size);
        assert_eq!(code.parity_rows(), code_size - message_size);
        assert_eq!(code.parity_cols(), code_size);
    }

    #[cfg(feature = "libote-compat")]
    #[test]
    fn test_compare_to_libote() {
        let message_size = 200;
        let exconv = ExConvCode::new(message_size);
        let code_size = exconv.conf.code_size;

        let mut data = vec![Block::ZERO; code_size];
        let mut rng = StdRng::seed_from_u64(2423);
        for _ in 0..100 {
            rng.fill_bytes(cast_slice_mut(&mut data));
            let mut data_libote = data.clone();
            exconv.dual_encode(&mut data);

            let mut libote_exconv = libote_codes::ExConvCode::new(
                message_size as u64,
                code_size as u64,
                exconv.conf.expander_weight as u64,
                exconv.conf.accumulator_size as u64,
            );
            libote_exconv.dual_encode_block(cast_slice_mut(&mut data_libote));

            assert_eq!(data, data_libote);
        }
    }

    #[cfg(feature = "libote-compat")]
    #[test]
    fn test_compare_to_libote_bytes() {
        let message_size = 200;
        let exconv = ExConvCode::new(message_size);
        let code_size = exconv.conf.code_size;

        let mut data = vec![u8::ZERO; code_size];
        let mut rng = StdRng::seed_from_u64(2423);
        for _ in 0..100 {
            rng.fill_bytes(cast_slice_mut(&mut data));
            let mut data_libote = data.clone();
            exconv.dual_encode(&mut data);

            let mut libote_exconv = libote_codes::ExConvCode::new(
                message_size as u64,
                code_size as u64,
                exconv.conf.expander_weight as u64,
                exconv.conf.accumulator_size as u64,
            );
            libote_exconv.dual_encode_byte(&mut data_libote);

            assert_eq!(data, data_libote);
        }
    }
}
