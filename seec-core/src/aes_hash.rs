//! Correlation robust AES hash.
//!
//! This implementation of a correlation robust AES hash function
//! is based on the findings of <https://eprint.iacr.org/2019/074>.
use std::sync::LazyLock;

use aes::{
    cipher::{BlockCipherEncrypt, Key, KeyInit},
    Aes128,
};

use crate::Block;

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
    pub fn cr_hash_blocks<const N: usize>(&self, x: &[Block; N]) -> [Block; N] {
        let mut blocks = x.map(|blk| blk.into());
        self.aes.encrypt_blocks(&mut blocks);

        let mut blocks = blocks.map(|enc_blk| enc_blk.into());
        for (enc_x, x) in blocks.iter_mut().zip(x) {
            *enc_x ^= *x;
        }
        blocks
    }

    pub fn cr_hash_slice_mut(&self, x: &mut [Block]) {
        let mut encrypted = vec![Default::default(); x.len()];
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
    // TODO: Is it sufficient to just choose some random key? This one was generated
    //  by just using `rand::thread_rng().gen()`
    let key = 193502124791825095790518994062991136444_u128
        .to_le_bytes()
        .into();
    AesHash::new(&key)
});
