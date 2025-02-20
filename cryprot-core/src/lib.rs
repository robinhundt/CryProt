#![cfg_attr(feature = "nightly", feature(test))]

pub mod aes_hash;
pub mod aes_rng;
pub mod alloc;
pub mod block;
pub mod buf;
pub mod random_oracle;
#[cfg(feature = "tokio-rayon")]
pub mod tokio_rayon;
pub mod transpose;
pub mod utils;
pub mod rand_compat;

pub use block::Block;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// https://github.com/RustCrypto/block-ciphers/blob/4da9b802de52a3326fdc74d559caddd57042fed2/aes/src/ni.rs#L43
pub const AES_PAR_BLOCKS: usize = 9;
#[cfg(target_arch = "aarch64")]
// https://github.com/RustCrypto/block-ciphers/blob/4da9b802de52a3326fdc74d559caddd57042fed2/aes/src/armv8.rs#L32
pub const AES_PAR_BLOCKS: usize = 21;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
// TODO what should the fallback be?
pub const AES_PAR_BLOCKS: usize = 4;

#[cfg(all(test, not(miri), target_feature = "aes"))]
mod tests {
    use aes::{
        cipher::{
            BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit, ParBlocksSizeUser,
        },
        Aes128,
    };

    use crate::AES_PAR_BLOCKS;

    #[test]
    fn aes_par_block_size() {
        use hybrid_array::typenum::Unsigned;

        struct GetParBlockSize;
        impl BlockSizeUser for GetParBlockSize {
            type BlockSize = aes::cipher::array::sizes::U16;
        }
        impl BlockCipherEncClosure for GetParBlockSize {
            fn call<B: aes::cipher::BlockCipherEncBackend<BlockSize = Self::BlockSize>>(
                self,
                _backend: &B,
            ) {
                assert_eq!(
                    AES_PAR_BLOCKS,
                    // size_of ArrayType<u8> is equal to its length
                    <<B as ParBlocksSizeUser>::ParBlocksSize as Unsigned>::USIZE,
                );
            }
        }
        let aes = Aes128::new(&Default::default());
        aes.encrypt_with_backend(GetParBlockSize);
    }
}
