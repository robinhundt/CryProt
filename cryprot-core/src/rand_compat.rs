//! Compatability wrapper between rand_core 0.10 and rand_core 0.6.
use rand::CryptoRng;
use rand_core::Rng;

/// Compatability wrapper between rand_core 0.10 and rand_core 0.6.
///
/// This implements the [`rand_core_0_6::RngCore`] and
/// [`rand_core_0_6::CryptoRng`] for any version 0.10 RNG that implements the
/// corresponding traits.
pub struct RngCompat<R>(pub R);

impl<R: Rng> rand_core_0_6::RngCore for RngCompat<R> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_0_6::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng> rand_core_0_6::CryptoRng for RngCompat<R> {}
