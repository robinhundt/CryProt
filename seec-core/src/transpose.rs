use std::{arch::x86_64::_mm_setr_epi8, array, mem::transmute};

use wide::{i64x2, i64x4, i8x16, i8x32};

pub fn transpose_bitmatrix(input: &[u8], rows: usize) -> Vec<u8> {
    let mut out = vec![0; input.len()];
    transpose_bitmatrix_into(input, &mut out, rows);
    out
}

/// Transpose a bit matrix.
///
/// # Panics
/// If the input is not divisable by 128.
/// If the number of columns (= input.len() * 8 / 128) is less than 128.
pub fn transpose_bitmatrix_into(input: &[u8], output: &mut [u8], rows: usize) {
    assert!(rows >= 32);
    assert_eq!(0, rows % 32);
    assert_eq!(0, input.len() % rows);
    let cols = input.len() * 8 / rows;
    assert!(cols >= 16);
    assert_eq!(
        0,
        cols % 8,
        "Number of bitmatrix columns must be divisable by 8. columns: {cols}"
    );

    unsafe {
        // let mut msbs = [0_u8; 4];
        let mut row: usize = 0;
        while row <= rows - 32 {
            let mut col = 0;
            while col < cols {
                let mut v = load_bytes(input, row, col, cols);
                // reverse iterator because we start writing the msb of each byte, then shift
                // left for i = 0, we write the previous lsb
                for i in (0..8).rev() {
                    // get msb of each byte
                    let msbs = v.move_mask();
                    // write msbs to output at transposed position as one i16
                    // let msb_i16 = i16::from_ne_bytes([msbs[0], msbs[1]]);
                    let idx = out(row, col + i, rows) as isize;
                    let out_ptr = output.as_mut_ptr().offset(idx) as *mut i32;
                    // ptr is potentially unaligned
                    out_ptr.write_unaligned(msbs);

                    // SAFETY: u8x16 and i64x2 have the same layout
                    //  we need to convert cast it, because there is no shift impl for u8x16
                    let v_i64x4 = &mut v as *mut _ as *mut i64x4;
                    // shift each byte by one to the left (by shifting it as two i64)
                    *v_i64x4 = *v_i64x4 << 1;
                }
                col += 8;
            }
            row += 32;
        }
    }
}

#[inline]
fn inp(x: usize, y: usize, cols: usize) -> usize {
    x * cols / 8 + y / 8
}
#[inline]
fn out(x: usize, y: usize, rows: usize) -> usize {
    y * rows / 8 + x / 8
}

#[inline]
// get col byte of row to row + 15
unsafe fn load_bytes(b: &[u8], row: usize, col: usize, cols: usize) -> i8x32 {
    unsafe {
        // if we have sse2 we use _mm_setr_epi8 and transmute to convert bytes
        // faster than from impl
        // #[cfg(target_feature = "sse2")]
        // {
        //     let v = _mm_setr_epi8(
        //         *b.get_unchecked(inp(row, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 1, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 2, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 3, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 4, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 5, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 6, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 7, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 8, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 9, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 10, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 11, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 12, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 13, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 14, col, cols)) as i8,
        //         *b.get_unchecked(inp(row + 15, col, cols)) as i8,
        //     );
        //     transmute(v)
        // }
        // #[cfg(not(target_feature = "sse2"))]
        {
            let bytes = array::from_fn(|i| *b.get_unchecked(inp(row + i, col, cols)) as i8);
            // let bytes = [
            //     *b.get_unchecked(inp(row, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 1, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 2, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 3, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 4, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 5, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 6, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 7, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 8, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 9, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 10, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 11, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 12, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 13, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 14, col, cols)) as i8,
            //     *b.get_unchecked(inp(row + 15, col, cols)) as i8,
            // ];
            i8x32::from(bytes)
        }
    }
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use crate::transpose::transpose_bitmatrix;

    fn arbitrary_bitmat(max_row: usize, max_col: usize) -> BoxedStrategy<(Vec<u8>, usize, usize)> {
        (
            (32..max_row).prop_map(|row| row / 32 * 32),
            (32..max_col).prop_map(|col| col / 32 * 32),
        )
            .prop_flat_map(|(rows, cols)| {
                (vec![any::<u8>(); rows * cols / 8], Just(rows), Just(cols))
            })
            .boxed()
    }

    proptest! {
        #[cfg(not(miri))]
        #[test]
        fn test_double_transpose((v, rows, cols) in arbitrary_bitmat(32 * 30, 32 * 30)) {
            let transposed = transpose_bitmatrix(&v, rows);
            let double_transposed = transpose_bitmatrix(&transposed, cols);

            prop_assert_eq!(v, double_transposed);
        }
    }

    #[test]
    fn test_double_transpose_miri() {
        let rows = 32;
        let cols = 32;
        let v = vec![0; rows * cols];
        let transposed = transpose_bitmatrix(&v, rows);
        let double_transposed = transpose_bitmatrix(&transposed, cols);
        assert_eq!(v, double_transposed);
    }
}

pub mod avx2 {
    use std::{arch::x86_64::*, hint::unreachable_unchecked};

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
    // matrix Only handles first two rows out of every 2^block_rows_shift rows
    // in each block
    unsafe fn avx_transpose_block_iter1(
        in_out: *mut __m256i,
        block_size_shift: usize,
        block_rows_shift: usize,
        j: usize,
    ) {
        if j < (1 << block_size_shift) && block_size_shift == 6 {
            let x = &mut *in_out.add(j / 2);
            let y = &mut *in_out.add(j / 2 + 32);

            let out_x = _mm256_unpacklo_epi64(*x, *y);
            let out_y = _mm256_unpackhi_epi64(*x, *y);
            *x = out_x;
            *y = out_y;
            return;
        }

        if block_size_shift == 0 || block_size_shift >= 6 || block_rows_shift < 1 {
            return;
        }

        // Calculate mask for the current block size
        let mut mask = (!0u64) << 32;
        for k in (block_size_shift as i32..=4).rev() {
            mask ^= mask >> (1 << k);
        }

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

    // Process a range of rows in the matrix
    unsafe fn avx_transpose_block_iter2(
        in_out: *mut __m256i,
        block_size_shift: usize,
        block_rows_shift: usize,
        n_rows: usize,
    ) {
        let mat_size = 1 << (block_size_shift + 1);

        for i in (0..n_rows).step_by(mat_size) {
            for j in (0..(1 << block_size_shift)).step_by(1 << block_rows_shift) {
                avx_transpose_block_iter1(in_out.add(i / 2), block_size_shift, block_rows_shift, j);
            }
        }
    }

    // Main transpose function for blocks within the matrix
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

    const AVX_BLOCK_SHIFT: usize = 4;
    const AVX_BLOCK_SIZE: usize = 1 << AVX_BLOCK_SHIFT;

    // Main entry point for matrix transpose
    pub fn avx_transpose128x128(in_out: &mut [__m256i; 64]) {
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

    #[cfg(test)]
    mod tests {
        use std::arch::x86_64::_mm256_setzero_si256;

        use rand::{rngs::StdRng, RngCore, SeedableRng};

        use super::avx_transpose128x128;

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
    }
}
