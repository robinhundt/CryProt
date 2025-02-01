use seec_core::Block;

/// The low 64-bit part of the constant block `y`.
const Y_LOW: u64 = 4234123421;
/// The modulus constant.
const MOD: u64 = 0b10000111; // 0x87

cpufeatures::new!(target_feature_sse2_pclmulqdq, "sse2", "pclmulqdq");

pub(crate) fn mul_const(x: Block) -> Block {
    if target_feature_sse2_pclmulqdq::get() {
        sse2::mul_const(x.into()).into()
    } else {
        scalar::mul_const_scalar(x.into()).into()
    }
}

#[cfg(any(target_arch = "x86",target_arch = "x86_64"))]
mod sse2 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    use super::{MOD, Y_LOW};

    pub(super) fn mul_const(x: __m128i) -> __m128i {
        unsafe {
            // Construct the constant block y = (high, low) = (0, 4234123421).
            let y = _mm_set_epi64x(0, Y_LOW as i64);
            // Construct modulus: load the 64-bit constant MOD into the low part of an
            // __m128i. (The high 64 bits will be 0.)
            let modulus = _mm_set_epi64x(0, MOD as i64);

            // _mm_clmulepi64_si128(x, y, 0x00) multiplies:
            //    low 64 bits of x  with low 64 bits of y.
            let xy1 = _mm_clmulepi64_si128(x, y, 0x00);
            // _mm_clmulepi64_si128(x, y, 0x01) multiplies:
            //    high 64 bits of x with low 64 bits of y.
            let xy2 = _mm_clmulepi64_si128(x, y, 0x01);

            // Combine: XOR xy1 with (xy2 shifted left by 8 bytes, i.e. 64 bits).
            let xy1 = _mm_xor_si128(xy1, _mm_slli_si128(xy2, 8));
            // Extract the high 64 bits from xy2 by shifting right 8 bytes.
            let xy2 = _mm_srli_si128(xy2, 8);

            // Reduce: Multiply the extracted high half by modulus.
            let tmp = _mm_clmulepi64_si128(xy2, modulus, 0x00);

            // Final result is the XOR of the combined product and the reduction.
            _mm_xor_si128(xy1, tmp)
        }
    }
}

// used in tests, but if we're not compiling tests these will otherwise be
// flagged as unused
#[allow(dead_code)]
mod scalar {
    use super::{MOD, Y_LOW};

    pub(super) fn mul_const_scalar(x: u128) -> u128 {
        let x_low = x as u64;
        let x_high = (x >> 64) as u64;

        let xy1 = clmul64(x_low, Y_LOW);
        let xy2 = clmul64(x_high, Y_LOW);

        let combined = xy1 ^ (xy2 << 64);
        let xy2_high = (xy2 >> 64) as u64;
        let tmp = clmul64(xy2_high, MOD);
        combined ^ tmp
    }

    /// Carry-less multiply (CLMUL) of two 64-bit numbers.
    ///
    /// This function computes the 128-bit product in GF(2) (i.e. without carry)
    /// by iterating over the bits of `b`. (For every set bit in `b`, it XORs
    /// in `a` shifted left by that bit index.)
    fn clmul64(a: u64, b: u64) -> u128 {
        let mut result: u128 = 0;
        for i in 0..64 {
            if (b >> i) & 1 == 1 {
                result ^= (a as u128) << i;
            }
        }
        result
    }
}

#[cfg(all(test, target_feature = "sse2", target_feature = "pclmulqdq"))]
mod tests {
    use std::arch::x86_64::*;

    use rand::Rng;

    use super::{scalar::mul_const_scalar, sse2};

    unsafe fn u128_to_m128i(x: u128) -> __m128i {
        // _mm_set_epi64x takes (hi: i64, lo: i64)
        let lo = x as u64;
        let hi = (x >> 64) as u64;
        _mm_set_epi64x(hi as i64, lo as i64)
    }

    unsafe fn m128i_to_u128(x: __m128i) -> u128 {
        // We store the __m128i to an array and reconstruct the u128.
        let mut arr = [0u64; 2];
        _mm_storeu_si128(arr.as_mut_ptr() as *mut __m128i, x);
        // arr[0] is the low 64 bits, arr[1] is the high 64 bits.
        (arr[1] as u128) << 64 | (arr[0] as u128)
    }

    /// Helper: Wrap the SSE version so we can compare with the scalar version.
    fn mul_const_sse_to_u128(x: u128) -> u128 {
        unsafe {
            let x_m128i = u128_to_m128i(x);
            let ret = sse2::mul_const(x_m128i);
            m128i_to_u128(ret)
        }
    }

    #[test]
    fn test_known_values() {
        // Some fixed test cases.
        let test_vals: [u128; 5] = [
            0,
            1,
            0xFFFFFFFFFFFFFFFF, // lower 64 bits set, high 64 bits = 0.
            0x123456789ABCDEF0FEDCBA9876543210,
            0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF,
        ];

        for &x in test_vals.iter() {
            let scalar = mul_const_scalar(x);
            let sse = mul_const_sse_to_u128(x);
            assert_eq!(scalar, sse, "Failed for x = {:#034x}", x);
        }
    }

    #[test]
    fn test_random_values() {
        let mut rng = rand::thread_rng();
        // Test 1000 random values.
        for _ in 0..1000 {
            let x: u128 = rng.gen();
            let scalar = mul_const_scalar(x);
            let sse = mul_const_sse_to_u128(x);
            assert_eq!(scalar, sse, "Mismatch for x = {:#034x}", x);
        }
    }
}
