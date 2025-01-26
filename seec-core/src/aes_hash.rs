//! Correlation robust AES hash.
//!
//! This implementation of a correlation robust AES hash function
//! is based on the findings of <https://eprint.iacr.org/2019/074>.
use std::sync::LazyLock;

use aes::{
    cipher::{BlockCipherEncrypt, Key, KeyInit},
    Aes128,
};
use bytemuck::Pod;

use crate::{
    utils::{allocate_zeroed_vec, xor_inplace},
    Block,
};

pub struct AesHash {
    aes: Aes128,
}

impl AesHash {
    /// Create a new `AesHash` with the given key.
    pub fn new(key: &Key<Aes128>) -> Self {
        Self {
            aes: Aes128::new(key),
        }
    }

    /// Compute the correlation robust hash of a block.
    ///
    /// # Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    pub fn cr_hash_block(&self, x: Block) -> Block {
        let mut x_enc = x.into();
        self.aes.encrypt_block(&mut x_enc);
        x ^ x_enc.into()
    }

    /// Compute the correlation robust hashes of multiple blocks.
    ///
    /// Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    pub fn cr_hash_blocks<const N: usize>(&self, x: &[Block; N]) -> [Block; N]
    where
        [Block; N]: Pod,
        [aes::Block; N]: Pod,
    {
        let mut blocks: [aes::Block; N] = bytemuck::cast(*x);
        self.aes.encrypt_blocks(&mut blocks);
        let mut blocks: [Block; N] = bytemuck::cast(blocks);
        xor_inplace(&mut blocks, x);
        blocks
    }

    /// Compute the correlation robust hashes of multiple blocks.
    ///
    /// Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    ///
    /// # Panics
    /// If N != out.len()
    pub fn cr_hash_blocks_b2b<const N: usize>(&self, inp: &[Block; N], out: &mut [Block])
    where
        [Block; N]: Pod,
        [aes::Block; N]: Pod,
    {
        assert_eq!(N, out.len());
        let inp_aes: &[aes::Block; N] = bytemuck::cast_ref(inp);
        let out_aes: &mut [aes::Block] = bytemuck::cast_slice_mut(out);
        self.aes
            .encrypt_blocks_b2b(inp_aes, out_aes)
            .expect("buffer have equal size");
        xor_inplace(out, inp);
    }

    pub fn cr_hash_slice_mut(&self, x: &mut [Block]) {
        let mut encrypted = allocate_zeroed_vec(x.len());
        self.aes
            .encrypt_blocks_b2b(bytemuck::cast_slice_mut(x), &mut encrypted)
            .unwrap();
        x.iter_mut()
            .zip(encrypted)
            .for_each(|(x, x_enc)| *x ^= x_enc.into());
    }
}

/// An `AesHash` with a fixed key.
pub static FIXED_KEY_HASH: LazyLock<AesHash> = LazyLock::new(|| {
    let key = 193502124791825095790518994062991136444_u128
        .to_le_bytes()
        .into();
    AesHash::new(&key)
});
