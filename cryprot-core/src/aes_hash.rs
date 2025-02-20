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

use crate::{utils::xor_inplace, Block, AES_PAR_BLOCKS};

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
        let mut tmp = [aes::Block::default(); AES_PAR_BLOCKS];

        for chunk in x.chunks_mut(AES_PAR_BLOCKS) {
            self.aes
                .encrypt_blocks_b2b(bytemuck::cast_slice(chunk), &mut tmp[..chunk.len()])
                .unwrap();
            chunk
                .iter_mut()
                .zip(tmp)
                .for_each(|(x, x_enc)| *x ^= x_enc.into());
        }
    }

    pub fn tccr_hash_slice_mut(&self, x: &mut [Block], mut tweak_fn: impl FnMut(usize) -> Block) {
        let mut tmp = [aes::Block::default(); AES_PAR_BLOCKS];
        for (chunk_idx, chunk) in x.chunks_mut(AES_PAR_BLOCKS).enumerate() {
            self.aes
                .encrypt_blocks_b2b(bytemuck::cast_slice(chunk), &mut tmp[..chunk.len()])
                .unwrap();
            chunk
                .iter_mut()
                .zip(&mut tmp)
                .enumerate()
                .for_each(|(idx, (dest, x_enc))| {
                    *dest = Block::from(*x_enc) ^ tweak_fn(chunk_idx * AES_PAR_BLOCKS + idx);
                });
            self.aes.encrypt_blocks(bytemuck::cast_slice_mut(chunk));
            chunk
                .iter_mut()
                .zip(tmp)
                .for_each(|(x, x_enc)| *x ^= x_enc.into());
        }
    }
}

/// An `AesHash` with a fixed key.
pub static FIXED_KEY_HASH: LazyLock<AesHash> = LazyLock::new(|| {
    let key = 193502124791825095790518994062991136444_u128
        .to_le_bytes()
        .into();
    AesHash::new(&key)
});
