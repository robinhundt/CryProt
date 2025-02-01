use expander::ExpanderCode;
use fast_aes_rng::FastAesRng;
use seec_core::block::Block;

use crate::GF2ops;

mod expander;
mod expander_modd;
mod fast_aes_rng;
mod gf128;

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
    pub systematic: bool,
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
            systematic: true,
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
            message_size,
            conf.code_size - message_size * (conf.systematic as usize),
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

    pub fn conf(&self) -> &ExConvCodeConfig {
        &self.conf
    }

    pub fn dual_encode<T: GF2ops>(&self, e: &mut [T]) {
        if self.conf.systematic {
            let (prefix, suffix) = e.split_at_mut(self.message_size);
            self.accumulate(suffix);
            self.expander.expand::<true, _>(suffix, prefix);
        } else {
            self.accumulate(e);
            let mut w = vec![T::ZERO; self.message_size];
            self.expander.expand::<false, _>(e, &mut w);
            e[..self.message_size].copy_from_slice(&w);
        }
    }

    fn accumulate<T: GF2ops>(&self, x: &mut [T]) {
        let size = self.conf.code_size - (self.conf.systematic as usize) * self.message_size;
        debug_assert_eq!(size, x.len());

        match self.conf.accumulator_size {
            24 => {
                self.accumulate_fixed::<24, _>(x, self.conf.seed);
                if self.conf.acc_twice {
                    self.accumulate_fixed::<24, _>(x, !self.conf.seed);
                }
            }
            _ => {
                self.accumulate_fixed::<0, _>(x, self.conf.seed);
                if self.conf.acc_twice {
                    self.accumulate_fixed::<0, _>(x, !self.conf.seed);
                }
            }
        }
    }

    fn accumulate_fixed<const ACCUMULATOR_SIZE: usize, T: GF2ops>(&self, x: &mut [T], seed: Block) {
        let mut i = 0;
        let main = x.len() - 1 - self.conf.accumulator_size;

        let mut rng = FastAesRng::new(seed);
        let mut mtx_coeffs = rng.bytes();

        while i < main {
            if mtx_coeffs.len() < self.conf.accumulator_size.div_ceil(8) {
                rng.refill();
                mtx_coeffs = rng.bytes();
            }

            if ACCUMULATOR_SIZE == 0 {
                self.acc_one_gen(x, i, mtx_coeffs, false);
            } else {
                self.acc_one::<ACCUMULATOR_SIZE, _>(x, i, mtx_coeffs, false);
            }
            mtx_coeffs = &mtx_coeffs[1..];
            i += 1;
        }

        while i < x.len() {
            if mtx_coeffs.len() < self.conf.accumulator_size.div_ceil(8) {
                rng.refill();
                mtx_coeffs = rng.bytes();
            }

            if ACCUMULATOR_SIZE == 0 {
                self.acc_one_gen(x, i, mtx_coeffs, true);
            } else {
                self.acc_one::<ACCUMULATOR_SIZE, _>(x, i, mtx_coeffs, true);
            }
            mtx_coeffs = &mtx_coeffs[1..];
            i += 1;
        }
    }

    fn acc_one_gen<T: GF2ops>(
        &self,
        x: &mut [T],
        i: usize,
        mut matrix_coeffs: &[u8],
        range_check: bool,
    ) {
        let size = x.len();
        let xi = x[i];
        let mut j = i + 1;
        if range_check && j >= size {
            j -= size;
        }

        let mut k = 0;

        while k + 7 < self.conf.accumulator_size {
            self.acc_one_8(x, i, j, matrix_coeffs[0], range_check);
            matrix_coeffs = &matrix_coeffs[1..];

            j += 8;
            if range_check && j >= size {
                j -= size;
            }
            k += 8;
        }

        while k < self.conf.accumulator_size {
            let mut b = matrix_coeffs[0];
            matrix_coeffs = &matrix_coeffs[1..];

            let mut p = 0;
            while p < 8 && k < self.conf.accumulator_size {
                if b & 1 != 0 {
                    x[j] ^= xi;
                }
                p += 1;
                k += 1;
                b >>= 1;
                j += 1;
                if range_check && j >= size {
                    j -= size;
                }
            }
            k += 1;
        }

        let idx = j;
        x[idx] ^= xi;
    }

    fn acc_one<const ACCUMULATOR_SIZE: usize, T: GF2ops>(
        &self,
        x: &mut [T],
        i: usize,
        mut matrix_coeffs: &[u8],
        range_check: bool,
    ) {
        let size = x.len();
        let mut j = i + 1;
        if range_check && j >= size {
            j -= size;
        }

        let mut k = 0;
        while k < ACCUMULATOR_SIZE {
            self.acc_one_8(x, i, j, matrix_coeffs[0], range_check);
            matrix_coeffs = &matrix_coeffs[1..];

            j += 8;
            if range_check && j >= size {
                j -= size;
            }
            k += 8;
        }

        let idx = j;
        x[idx] ^= x[i];
    }

    fn acc_one_8<T: GF2ops>(&self, x: &mut [T], i: usize, j: usize, b: u8, range_check: bool) {
        let size = x.len();
        let xi = x[i];
        let mut js = [j, j + 1, j + 2, j + 3, j + 4, j + 5, j + 6, j + 7];

        if range_check {
            for j in js.iter_mut() {
                if *j >= size {
                    *j -= size;
                }
            }
        }

        let b0 = b & 1;
        let b1 = b & 2;
        let b2 = b & 4;
        let b3 = b & 8;
        let b4 = b & 16;
        let b5 = b & 32;
        let b6 = b & 64;
        let b7 = b & 128;

        // I've tried replacing these index operations with unchecked ones, but there is
        // no measurable performance boost
        if b0 != 0 {
            x[js[0]] ^= xi;
        }
        if b1 != 0 {
            x[js[1]] ^= xi;
        }
        if b2 != 0 {
            x[js[2]] ^= xi;
        }
        if b3 != 0 {
            x[js[3]] ^= xi;
        }
        if b4 != 0 {
            x[js[4]] ^= xi;
        }
        if b5 != 0 {
            x[js[5]] ^= xi;
        }
        if b6 != 0 {
            x[js[6]] ^= xi;
        }
        if b7 != 0 {
            x[js[7]] ^= xi;
        }
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::cast_slice_mut;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use seec_core::block::Block;

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
        assert!(code.conf.systematic);
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

            let mut libote_exconv = libote::ExConvCode::new(
                message_size as u64,
                code_size as u64,
                exconv.conf.expander_weight as u64,
                exconv.conf.accumulator_size as u64,
            );
            libote_exconv.dual_encode_block(cast_slice_mut(&mut data_libote));

            assert_eq!(data, data_libote);
        }
    }

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

            let mut libote_exconv = libote::ExConvCode::new(
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
