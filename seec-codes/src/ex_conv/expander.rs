use seec_core::Block;

use super::expander_modd::ExpanderModd;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpanderCode {
    // the seed that generates the code.
    seed: Block,
    // The message size of the code. K.
    message_size: u64,
    // The codeword size of the code. n.
    code_size: u64,
    // The row weight of the B matrix.
    expander_weight: u64,
    regular: bool,
}

impl ExpanderCode {
    pub(crate) fn new(
        message_size: u64,
        code_size: u64,
        expander_weight: u64,
        regular_expander: bool,
        seed: Block,
    ) -> Self {
        Self {
            seed,
            message_size,
            code_size,
            expander_weight,
            regular: regular_expander,
        }
    }

    pub(crate) fn expand<const ADD: bool>(&self, inp: &[Block], mut out: &mut [Block]) {
        let main = self.message_size / 8 * 8;
        let mut i = 0;
        let mut reg = 0;
        let mut uni = self.expander_weight;
        let mut step = 0;
        let mut uni_gen = ExpanderModd::new(self.seed, self.code_size);
        let mut reg_gen = if self.regular {
            uni = self.expander_weight / 2;
            reg = self.expander_weight - uni;
            step = self.code_size / reg;
            Some(ExpanderModd::new(
                self.seed ^ Block::from([23421341, 342342134]),
                step,
            ))
        } else {
            None
        };

        if !ADD {
            out.fill(Block::ZERO);
        }

        while i < main {
            if let Some(reg_gen) = &mut reg_gen {
                for j in 0..reg {
                    let mut rr = [0; 8];
                    for r in &mut rr {
                        *r = reg_gen.get() + j * step;
                    }
                    for (o, r) in out.iter_mut().zip(rr) {
                        *o ^= inp[r as usize];
                    }
                }
            }

            for _ in 0..uni {
                let mut rr = [0; 8];
                for r in &mut rr {
                    *r = uni_gen.get();
                }
                for (o, r) in out.iter_mut().zip(rr) {
                    *o ^= inp[r as usize];
                }
            }
            i += 8;
            out = &mut out[8..];
        }

        while i < self.message_size {
            if let Some(reg_gen) = &mut reg_gen {
                for j in 0..reg {
                    out[0] ^= inp[(reg_gen.get() + j * step) as usize];
                }
            }

            for _j in 0..uni {
                out[0] ^= inp[uni_gen.get() as usize];
            }

            i += 1;
            out = &mut out[1..];
        }
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::cast_slice_mut;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::*;

    // TODO this test cases are very basic and don't correctly test the correctness
    // of the expander...

    #[test]
    fn test_basic_expansion() {
        // Test case 1: Basic expansion with regular expander
        let seed = Block::from([123456789, 987654321]);
        let code = ExpanderCode::new(16, 32, 4, true, seed);

        let mut input = vec![Block::ZERO; 32];
        StdRng::seed_from_u64(2342).fill_bytes(cast_slice_mut(&mut input));

        let mut output = vec![Block::ZERO; 16];

        code.expand::<false>(&input, &mut output);

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
        let code = ExpanderCode::new(8, 16, 3, false, seed);

        let mut input = vec![Block::ZERO; 16];
        StdRng::seed_from_u64(2342).fill_bytes(cast_slice_mut(&mut input));
        let mut output = vec![Block::ZERO; 8];

        code.expand::<false>(&input, &mut output);

        assert_ne!(input, output);
        assert!(
            output.iter().all(|&x| x != Block::ZERO),
            "Output should not contain non-zero elements"
        );
    }

    #[test]
    fn test_additive_expansion() {
        // Test case 3: Testing additive expansion (ADD = true)
        let seed = Block::from([333333333, 444444444]);
        let code = ExpanderCode::new(32, 64, 6, true, seed);

        let mut input = vec![Block::ZERO; 64];
        StdRng::seed_from_u64(2342).fill_bytes(cast_slice_mut(&mut input));

        let mut output = vec![Block::from([2, 2]); 32]; // Pre-filled output
        let original_output = output.clone();

        code.expand::<true>(&input, &mut output);

        assert_ne!(input, output);
        assert_ne!(original_output, output);
        assert!(
            output.iter().all(|&x| x != Block::ZERO),
            "Output should not contain non-zero elements"
        );
    }
}
