

// #[cfg(target_feature = "avx2")]
pub mod avx2;
pub mod portable;


pub fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    #[cfg(target_feature = "avx2")]
    avx2::transpose_bitmatrix(input, output, rows);
    #[cfg(not(target_feature = "avx2"))]
    portable::transpose_bitmatrix(input, output, rows);
}