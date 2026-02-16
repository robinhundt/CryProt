use cryprot_core::Block;

use super::expander_modd::ExpanderModd;
use crate::Coeff;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpanderCode {
    // the seed that generates the code.
    seed: Block,
    // The codeword size of the code. n.
    code_size: usize,
    // The row weight of the B matrix.
    expander_weight: usize,
    regular: bool,
}

impl ExpanderCode {
    pub(crate) fn new(
        code_size: usize,
        expander_weight: usize,
        regular_expander: bool,
        seed: Block,
    ) -> Self {
        Self {
            seed,
            code_size,
            expander_weight,
            regular: regular_expander,
        }
    }

    pub(crate) fn expand<T: Coeff>(&self, inp: &[T], out: &mut [T]) {
        #[cfg(not(feature = "libote-compat"))]
        self.expand_simple(inp, out);
        #[cfg(feature = "libote-compat")]
        self.expand_libote(inp, out);
    }

    #[cfg(not(feature = "libote-compat"))]
    fn expand_simple<T: Coeff>(&self, inp: &[T], out: &mut [T]) {
        let mut uni = self.expander_weight;
        let mut uni_gen = ExpanderModd::new(self.seed, self.code_size as u64);
        let mut reg_gen = if self.regular {
            uni = self.expander_weight / 2;
            let reg = self.expander_weight - uni;
            let step = self.code_size / reg;
            let reg_gen =
                ExpanderModd::new(self.seed ^ Block::from([23421341, 342342134]), step as u64);
            Some((reg_gen, reg, step))
        } else {
            None
        };

        for out in out.iter_mut() {
            if let Some((ref mut reg_gen, reg, step)) = reg_gen {
                for j in 0..reg {
                    *out ^= inp[reg_gen.get() + j * step];
                }
            }

            for _ in 0..uni {
                *out ^= inp[uni_gen.get()];
            }
        }
    }

    #[cfg(feature = "libote-compat")]
    // Preserves compatability with libote for testing purposes. expand_simple is
    // simpler and faster
    fn expand_libote<T: Coeff>(&self, inp: &[T], out: &mut [T]) {
        use seq_macro::seq;

        let mut uni = self.expander_weight;
        let mut uni_gen = ExpanderModd::new(self.seed, self.code_size as u64);
        let mut reg_gen = if self.regular {
            uni = self.expander_weight / 2;
            let reg = self.expander_weight - uni;
            let step = self.code_size / reg;
            let reg_gen =
                ExpanderModd::new(self.seed ^ Block::from([23421341, 342342134]), step as u64);
            Some((reg_gen, reg, step))
        } else {
            None
        };

        let mut chunk_iter = out.chunks_exact_mut(8);
        for out_chunk in chunk_iter.by_ref() {
            if let Some((ref mut reg_gen, reg, step)) = reg_gen {
                for j in 0..reg {
                    let mut rr = [0; 8];
                    for r in &mut rr {
                        *r = reg_gen.get() + j * step;
                    }
                    unsafe {
                        seq!(N in 0..8 {
                            *out_chunk.get_unchecked_mut(N) ^= *inp.get_unchecked(rr[N]) ;
                        });
                    }
                }
            }

            for _ in 0..uni {
                let mut rr = [0; 8];
                for r in &mut rr {
                    *r = uni_gen.get();
                }
                unsafe {
                    seq!(N in 0..8 {
                        *out_chunk.get_unchecked_mut(N) ^= *inp.get_unchecked(rr[N]) ;
                    });
                }
            }
        }

        for out in chunk_iter.into_remainder() {
            if let Some((ref mut reg_gen, reg, step)) = reg_gen {
                for j in 0..reg {
                    *out ^= inp[reg_gen.get() + j * step];
                }
            }

            for _j in 0..uni {
                *out ^= inp[uni_gen.get()];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::cast_slice_mut;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;

    // TODO this test cases are very basic and don't correctly test the correctness
    // of the expander...

    #[test]
    fn test_basic_expansion() {
        // Test case 1: Basic expansion with regular expander
        let seed = Block::from([123456789, 987654321]);
        let code = ExpanderCode::new(32, 4, true, seed);

        let mut input = vec![Block::ZERO; 32];
        StdRng::seed_from_u64(2342).fill_bytes(cast_slice_mut(&mut input));

        let mut output = vec![Block::ZERO; 16];

        code.expand(&input, &mut output);

        assert_ne!(input, output);
        assert!(
            output.iter().all(|&x| x != Block::ZERO),
            "Output should not contain non-zero elements"
        );
    }

    #[test]
    fn test_irregular_expander() {
        // Test case 2: Expansion with irregular expander
        let seed = Block::from([111111111, 222222222]);
        let code = ExpanderCode::new(16, 3, false, seed);

        let mut input = vec![Block::ZERO; 16];
        StdRng::seed_from_u64(2342).fill_bytes(cast_slice_mut(&mut input));
        let mut output = vec![Block::ZERO; 8];

        code.expand(&input, &mut output);

        assert_ne!(input, output);
        assert!(
            output.iter().all(|&x| x != Block::ZERO),
            "Output should not contain non-zero elements"
        );
    }
}
