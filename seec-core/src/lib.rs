pub mod aes_hash;
pub mod aes_rng;
pub mod alloc;
pub mod block;
pub mod random_oracle;
#[doc(hidden)]
#[cfg(feature = "__testing")]
pub mod test_utils;
#[cfg(feature = "tokio-rayon")]
pub mod tokio_rayon;
pub mod transpose;
pub mod utils;

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

#[cfg(test)]
mod tests {
    use std::mem;

    use aes::{
        cipher::{
            BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit, ParBlocksSizeUser,
        },
        Aes128,
    };
    use hybrid_array::ArraySize;

    use crate::AES_PAR_BLOCKS;

    #[cfg(target_feature = "aes")]
    #[test]
    fn aes_par_block_size() {
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
                    mem::size_of::<
                        <<B as ParBlocksSizeUser>::ParBlocksSize as ArraySize>::ArrayType<u8>,
                    >()
                );
            }
        }
        let aes = Aes128::new(&Default::default());
        aes.encrypt_with_backend(GetParBlockSize);
    }
}
