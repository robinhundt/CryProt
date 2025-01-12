use std::{arch::x86_64::_mm_setr_epi8, mem::transmute};

use wide::{i64x2, i8x16};

// #[cfg(target_feature = "avx2")]
pub mod avx2;
pub mod portable;


pub fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    #[cfg(target_feature = "avx2")]
    avx2::transpose_bitmatrix(input, output, rows);
    #[cfg(not(target_feature = "avx2"))]
    portable::transpose_bitmatrix(input, output, rows);
}