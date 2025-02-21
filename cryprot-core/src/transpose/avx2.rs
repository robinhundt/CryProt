use std::{arch::x86_64::*, hint::unreachable_unchecked};

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn _mm256_slli_epi64_var_shift(a: __m256i, shift: usize) -> __m256i {
    unsafe {
        match shift {
            2 => _mm256_slli_epi64::<2>(a),
            4 => _mm256_slli_epi64::<4>(a),
            8 => _mm256_slli_epi64::<8>(a),
            16 => _mm256_slli_epi64::<16>(a),
            32 => _mm256_slli_epi64::<32>(a),
            _ => unreachable_unchecked(),
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn _mm256_srli_epi64_var_shift(a: __m256i, shift: usize) -> __m256i {
    unsafe {
        match shift {
            2 => _mm256_srli_epi64::<2>(a),
            4 => _mm256_srli_epi64::<4>(a),
            8 => _mm256_srli_epi64::<8>(a),
            16 => _mm256_srli_epi64::<16>(a),
            32 => _mm256_srli_epi64::<32>(a),
            _ => unreachable_unchecked(),
        }
    }
}

// Transpose a 2^block_size_shift x 2^block_size_shift block within a larger
// matrix Only handles first two rows out of every 2^block_rows_shift rows in
// each block
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx_transpose_block_iter1(
    in_out: *mut __m256i,
    block_size_shift: usize,
    block_rows_shift: usize,
    j: usize,
) {
    if j < (1 << block_size_shift) && block_size_shift == 6 {
        unsafe {
            let x = &mut *in_out.add(j / 2);
            let y = &mut *in_out.add(j / 2 + 32);

            let out_x = _mm256_unpacklo_epi64(*x, *y);
            let out_y = _mm256_unpackhi_epi64(*x, *y);
            *x = out_x;
            *y = out_y;
            return;
        }
    }

    if block_size_shift == 0 || block_size_shift >= 6 || block_rows_shift < 1 {
        return;
    }

    // Calculate mask for the current block size
    let mut mask = (!0u64) << 32;
    for k in (block_size_shift as i32..=4).rev() {
        mask ^= mask >> (1 << k);
    }

    unsafe {
        let x = &mut *in_out.add(j / 2);
        let y = &mut *in_out.add(j / 2 + (1 << (block_size_shift - 1)));

        // Special case for 2x2 blocks (block_size_shift == 1)
        if block_size_shift == 1 {
            let u = _mm256_permute2x128_si256(*x, *y, 0x20);
            let v = _mm256_permute2x128_si256(*x, *y, 0x31);

            let mut diff = _mm256_xor_si256(u, _mm256_slli_epi16(v, 1));
            diff = _mm256_and_si256(diff, _mm256_set1_epi16(0b1010101010101010_u16 as i16));
            let u = _mm256_xor_si256(u, diff);
            let v = _mm256_xor_si256(v, _mm256_srli_epi16(diff, 1));

            *x = _mm256_permute2x128_si256(u, v, 0x20);
            *y = _mm256_permute2x128_si256(u, v, 0x31);
        }

        let mut diff = _mm256_xor_si256(*x, _mm256_slli_epi64_var_shift(*y, 1 << block_size_shift));
        diff = _mm256_and_si256(diff, _mm256_set1_epi64x(mask as i64));
        *x = _mm256_xor_si256(*x, diff);
        *y = _mm256_xor_si256(*y, _mm256_srli_epi64_var_shift(diff, 1 << block_size_shift));
    }
}

#[inline] // Process a range of rows in the matrix
#[target_feature(enable = "avx2")]
unsafe fn avx_transpose_block_iter2(
    in_out: *mut __m256i,
    block_size_shift: usize,
    block_rows_shift: usize,
    n_rows: usize,
) {
    let mat_size = 1 << (block_size_shift + 1);

    for i in (0..n_rows).step_by(mat_size) {
        for j in (0..(1 << block_size_shift)).step_by(1 << block_rows_shift) {
            unsafe {
                avx_transpose_block_iter1(in_out.add(i / 2), block_size_shift, block_rows_shift, j);
            }
        }
    }
}

#[inline] // Main transpose function for blocks within the matrix
#[target_feature(enable = "avx2")]
unsafe fn avx_transpose_block(
    in_out: *mut __m256i,
    block_size_shift: usize,
    mat_size_shift: usize,
    block_rows_shift: usize,
    mat_rows_shift: usize,
) {
    if block_size_shift >= mat_size_shift {
        return;
    }

    // Process current block size
    let total_rows = 1 << (mat_rows_shift + mat_size_shift);

    unsafe {
        avx_transpose_block_iter2(in_out, block_size_shift, block_rows_shift, total_rows);

        // Recursively process larger blocks
        avx_transpose_block(
            in_out,
            block_size_shift + 1,
            mat_size_shift,
            block_rows_shift,
            mat_rows_shift,
        );
    }
}

const AVX_BLOCK_SHIFT: usize = 4;
const AVX_BLOCK_SIZE: usize = 1 << AVX_BLOCK_SHIFT;

// Main entry point for matrix transpose
#[target_feature(enable = "avx2")]
pub unsafe fn avx_transpose128x128(in_out: &mut [__m256i; 64]) {
    const MAT_SIZE_SHIFT: usize = 7;
    unsafe {
        let in_out = in_out.as_mut_ptr();
        for i in (0..64).step_by(AVX_BLOCK_SIZE) {
            avx_transpose_block(
                in_out.add(i),
                1,
                MAT_SIZE_SHIFT - AVX_BLOCK_SHIFT,
                1,
                AVX_BLOCK_SHIFT + 1 - (MAT_SIZE_SHIFT - AVX_BLOCK_SHIFT),
            );
        }

        // Process larger blocks
        let block_size_shift = MAT_SIZE_SHIFT - AVX_BLOCK_SHIFT;

        // Special case for full matrix
        for i in 0..(1 << (block_size_shift - 1)) {
            avx_transpose_block(
                in_out.add(i),
                block_size_shift,
                MAT_SIZE_SHIFT,
                block_size_shift,
                0,
            );
        }
    }
}

#[target_feature(enable = "avx2")]
pub unsafe fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    assert_eq!(input.len(), output.len());
    let cols = input.len() * 8 / rows;
    assert_eq!(0, cols % 128);
    assert_eq!(0, rows % 128);
    let mut buf = [unsafe { _mm256_setzero_si256() }; 64];
    let in_stride = cols / 8;
    let out_stride = rows / 8;

    // Number of 128x128 bit squares
    let r_main = rows / 128;
    let c_main = cols / 128;

    for i in 0..r_main {
        for j in 0..c_main {
            // Process each 128x128 bit square
            unsafe {
                let src_ptr = input.as_ptr().add(i * 128 * in_stride + j * 16);

                let buf_u8_ptr = buf.as_mut_ptr() as *mut u8;

                // Copy 128 rows into buffer
                for k in 0..128 {
                    let src_row = src_ptr.add(k * in_stride);
                    std::ptr::copy_nonoverlapping(src_row, buf_u8_ptr.add(k * 16), 16);
                }
            }
            // SAFETY: avx2 is enabled
            unsafe {
                // Transpose the 128x128 bit square
                avx_transpose128x128(&mut buf);
            }

            unsafe {
                // needs to be recreated because prev &mut borrow invalidates ptr
                let buf_u8_ptr = buf.as_mut_ptr() as *mut u8;
                // Copy transposed data to output
                let dst_ptr = output.as_mut_ptr().add(j * 128 * out_stride + i * 16);
                for k in 0..128 {
                    let dst_row = dst_ptr.add(k * out_stride);
                    std::ptr::copy_nonoverlapping(buf_u8_ptr.add(k * 16), dst_row, 16);
                }
            }
        }
    }
}

#[cfg(all(test, target_feature = "avx2"))]
mod tests {
    use std::arch::x86_64::_mm256_setzero_si256;

    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use super::{avx_transpose128x128, transpose_bitmatrix};

    #[test]
    fn test_avx_transpose128() {
        unsafe {
            let mut v = [_mm256_setzero_si256(); 64];
            StdRng::seed_from_u64(42).fill_bytes(bytemuck::cast_slice_mut(&mut v));

            let orig = v.clone();
            avx_transpose128x128(&mut v);
            avx_transpose128x128(&mut v);
            let mut failed = false;
            for (i, (o, t)) in orig.into_iter().zip(v).enumerate() {
                let o = bytemuck::cast::<_, [u128; 2]>(o);
                let t = bytemuck::cast::<_, [u128; 2]>(t);
                if o != t {
                    eprintln!("difference in block {i}");
                    eprintln!("orig: {o:?}");
                    eprintln!("tran: {t:?}");
                    failed = true;
                }
            }
            if failed {
                panic!("double transposed is different than original")
            }
        }
    }

    #[test]
    fn test_avx_transpose() {
        let rows = 128 * 2;
        let cols = 128 * 2;
        let mut v = vec![0_u8; rows * cols / 8];
        StdRng::seed_from_u64(42).fill_bytes(&mut v);

        let mut avx_transposed = v.clone();
        let mut sse_transposed = v.clone();
        unsafe {
            transpose_bitmatrix(&v, &mut avx_transposed, rows);
        }
        crate::transpose::portable::transpose_bitmatrix(&v, &mut sse_transposed, rows);

        assert_eq!(sse_transposed, avx_transposed);
    }
}
