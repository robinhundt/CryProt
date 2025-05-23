//! Implementation of AVX2 BitMatrix transpose based on libOTe.
use std::arch::x86_64::*;

use bytemuck::{must_cast_slice, must_cast_slice_mut};
use seq_macro::seq;

/// Performs a 2x2 bit transpose operation on two 256-bit vectors representing a
/// 4x128 matrix.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose_2x2_matrices(x: &mut __m256i, y: &mut __m256i) {
    // x = [x_H | x_L] and y = [y_H | y_L]
    // u = [y_L | x_L] u is the low 128 bits of x and y
    let u = _mm256_permute2x128_si256(*x, *y, 0x20);
    // v = [y_H | x_H] v is the high 128 bits of x and y
    let v = _mm256_permute2x128_si256(*x, *y, 0x31);
    // Shift v by one left so each element in at (i, j) aligns with (i+1, j-1) and
    // compute the difference. the row shift i+1 is done by the permute
    // instructions before and the column by the sll instruction
    let mut diff = _mm256_xor_si256(u, _mm256_slli_epi16(v, 1));
    // select all odd indices of diff and zero out even indices. the idea is to
    // calculate the difference of all odd numbered indices j of the even
    // numbered row i with the even numbered indices j-1 in row i+1.
    // These are precisely the elements in the 2x2 matrices that make up x and y
    // that potentially need to be swapped for the transpose if they differ
    diff = _mm256_and_si256(diff, _mm256_set1_epi16(0b1010101010101010_u16 as i16));
    // perform the swaps in u, which corresponds the lower bits of x and y by XORing
    // the diff
    let u = _mm256_xor_si256(u, diff);
    // for the bottom row in the 2x2 matrices (the high bits of x and y) we need to
    // shift the diff by 1 to the right so it aligns with the even numbered indices
    let v = _mm256_xor_si256(v, _mm256_srli_epi16(diff, 1));
    // the permuted 2x2 matrices are split over u and v, with the upper row in u and
    // the lower in v. We perform the same permutation as in the beginning, thereby
    // writing the 2x2 permuted bits of x and y back
    *x = _mm256_permute2x128_si256(u, v, 0x20);
    *y = _mm256_permute2x128_si256(u, v, 0x31);
}

/// Performs a general bit-level transpose.
///
/// `SHIFT_AMOUNT` is the constant shift value (e.g., 2, 4, 8, 16, 32) for the
/// intrinsics. `MASK` is the bitmask for the XOR-swap.
#[inline]
#[target_feature(enable = "avx2")]
fn partial_swap_sub_matrices<const SHIFT_AMOUNT: i32, const MASK: u64>(
    x: &mut __m256i,
    y: &mut __m256i,
) {
    // calculate the diff of the bits that need to be potentially swapped
    let mut diff = _mm256_xor_si256(*x, _mm256_slli_epi64::<SHIFT_AMOUNT>(*y));
    diff = _mm256_and_si256(diff, _mm256_set1_epi64x(MASK as i64));
    // swap the bits in x by xoring the difference
    *x = _mm256_xor_si256(*x, diff);
    // and in y
    *y = _mm256_xor_si256(*y, _mm256_srli_epi64::<SHIFT_AMOUNT>(diff));
}

/// Performs a partial 64x64 bit matrix swap. This is used to swap the rows in
/// the upper right quadrant with those of the lower left in the 128x128 matrix.
#[inline]
#[target_feature(enable = "avx2")]
fn partial_swap_64x64_matrices(x: &mut __m256i, y: &mut __m256i) {
    let out_x = _mm256_unpacklo_epi64(*x, *y);
    let out_y = _mm256_unpackhi_epi64(*x, *y);
    *x = out_x;
    *y = out_y;
}

/// Transpose a 128x128 bit matrix using AVX2 intrinsics.
///
/// # Safety
/// AVX2 needs to be enabled.
#[target_feature(enable = "avx2")]
pub fn avx_transpose128x128(in_out: &mut [__m256i; 64]) {
    // This algorithm implements a bit-transpose of a 128x128 bit matrix using a
    // divide-and-conquer algorithm. The idea is that for
    // A = [ A B ]
    //     [ C D ]
    // A^T is equal to
    //     [ A^T C^T ]
    //     [ B^T D^T ]
    //
    // We first divide our matrix into 2x2 bit matrices which we transpose at the
    // bit level. Then we swap the 2x2 bit matrices to complete a 4x4
    // transpose. We swap the 4x4 bit matrices to complete a 8x8 transpose and so on
    // until we swap 64x64 bit matrices and thus complete the intended 128x128 bit
    // transpose.

    // Part 1: Specialized 2x2 block transpose transposing individual bits
    for chunk in in_out.chunks_exact_mut(2) {
        if let [x, y] = chunk {
            transpose_2x2_matrices(x, y);
        } else {
            unreachable!("chunk size is 2")
        }
    }

    // Phases 1-5: swap sub-matrices of size 2x2, 4x4, 8x8, 16x16, 32x32 bit
    // Using seq_macro to reduce repetition
    seq!(N in 1..=5 {
        const SHIFT_~N: i32 = 1 << N;
        // Our mask selects the part of the sub-matrix that needs to be potentially
        // swapped allong the diagonal. The lower 2^SHIFT bits are 0 and the following
        // 2^SHIFT bits are 1, repeated to a 64 bit mask
        const MASK_~N: u64 = match N {
            1 => mask(0b1100, 4),
            2 => mask(0b11110000, 8),
            3 => mask(0b1111111100000000, 16),
            4 => mask(0b11111111111111110000000000000000, 32),
            5 => 0xffffffff00000000,
            _ => unreachable!(),
        };
        // The offset between x and y for matrix rows that need to be swapped in terms
        // of 256 bit elements. In the first iteration we swap the 2x2 matrices that
        // are at positions in_out[i] and in_out[j], so the offset is 1. For 4x4 matrices
        // the offset is 2
        const OFFSET~N: usize = 1 << (N - 1);

        for chunk in in_out.chunks_exact_mut(2 * OFFSET~N) {
            let (x_chunk, y_chunk) = chunk.split_at_mut(OFFSET~N);
            // For larger matrices, and larger offsets, we need to iterate over all
            // rows of the sub-matrices
            for (x, y) in x_chunk.iter_mut().zip(y_chunk.iter_mut()) {
                partial_swap_sub_matrices::<SHIFT_~N, MASK_~N>(x, y);
            }
        }
    });

    // Phase 6: swap 64x64 bit-matrices therfore completing the 128x128 bit
    // transpose
    const SHIFT_6: usize = 6;
    const OFFSET_6: usize = 1 << (SHIFT_6 - 1); // 32

    for chunk in in_out.chunks_exact_mut(2 * OFFSET_6) {
        let (x_chunk, y_chunk) = chunk.split_at_mut(OFFSET_6);
        for (x, y) in x_chunk.iter_mut().zip(y_chunk.iter_mut()) {
            partial_swap_64x64_matrices(x, y);
        }
    }
}

/// Create a u64 bit mask based on the pattern which is repeated to fill the u54
const fn mask(pattern: u64, pattern_len: u32) -> u64 {
    let mut mask = pattern;
    let mut current_block_len = pattern_len;

    // We keep doubling the effective length of our repeating block
    // until it covers 64 bits.
    while current_block_len < 64 {
        mask = (mask << current_block_len) | mask;
        current_block_len *= 2;
    }

    mask
}

/// Transpose a bit matrix of arbitrary (but constrained) dimensions using AVX2.
///
/// # Panics
/// If the input is not divisible by 128.
/// If the number of columns (= input.len() * 8 / rows) is less than 128.
/// If `input.len() != output.len()`
///
/// # Safety
/// AVX2 instruction set must be available.
#[target_feature(enable = "avx2")]
pub fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    assert_eq!(input.len(), output.len());
    let cols = input.len() * 8 / rows;
    assert_eq!(
        0,
        cols % 128,
        "Number of columns must be a multiple of 128."
    );
    assert_eq!(0, rows % 128, "Number of rows must be a multiple of 128.");
    assert!(cols >= 128, "Number of columns must be at least 128.");

    // Buffer to hold a single 128x128 bit square (64 __m256i registers = 2048
    // bytes)
    let mut buf = [_mm256_setzero_si256(); 64];
    let in_stride = cols / 8; // Stride in bytes for input rows
    let out_stride = rows / 8; // Stride in bytes for output rows

    // Number of 128x128 bit squares in rows and columns
    let r_main = rows / 128;
    let c_main = cols / 128;

    // Iterate through each 128x128 bit square in the matrix
    // Row block index
    for i in 0..r_main {
        // Column block index
        for j in 0..c_main {
            // Load 128x128 bit sub-matrix into `buf`
            let input_block_start_byte_idx = i * 128 * in_stride + j * 16;
            let buf_as_bytes: &mut [u8] = must_cast_slice_mut(&mut buf);

            for k in 0..128 {
                let src_slice = &input[input_block_start_byte_idx + k * in_stride
                    ..input_block_start_byte_idx + k * in_stride + 16];
                buf_as_bytes[k * 16..(k + 1) * 16].copy_from_slice(src_slice);
            }

            // Transpose the 128x128 bit sub-matrix in `buf`
            avx_transpose128x128(&mut buf);

            // Copy the transposed data from `buf` to the output slice.
            let output_block_start_byte_idx = j * 128 * out_stride + i * 16;
            let buf_as_bytes: &[u8] = must_cast_slice(&buf); // Now read-only

            for k in 0..128 {
                let src_slice = &buf_as_bytes[k * 16..(k + 1) * 16];
                let dst_slice = &mut output[output_block_start_byte_idx + k * out_stride
                    ..output_block_start_byte_idx + k * out_stride + 16];
                dst_slice.copy_from_slice(src_slice);
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
