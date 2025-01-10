use std::{arch::x86_64::_mm_setr_epi8, mem::transmute};

use wide::{i64x2, i8x16};

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
    assert!(rows >= 16);
    assert_eq!(0, rows % 16);
    assert_eq!(0, input.len() % rows);
    let cols = input.len() * 8 / rows;
    assert!(cols >= 16);
    assert_eq!(
        0,
        cols % 8,
        "Number of bitmatrix columns must be divisable by 8. columns: {cols}"
    );

    unsafe {
        let mut msbs = [0_u8; 4];
        let mut row: usize = 0;
        while row <= rows - 16 {
            let mut col = 0;
            while col < cols {
                let mut v = load_bytes(input, row, col, cols);
                // reverse iterator because we start writing the msb of each byte, then shift
                // left for i = 0, we write the previous lsb
                for i in (0..8).rev() {
                    // get msb of each byte
                    msbs = v.move_mask().to_le_bytes();
                    // dbg!(msbs);
                    // write msbs to output at transposed position as one i16
                    let msb_i16 = i16::from_ne_bytes([msbs[0], msbs[1]]);
                    let idx = out(row, col + i, rows) as isize;
                    let out_ptr = output.as_mut_ptr().offset(idx) as *mut i16;
                    // ptr is potentially unaligned
                    out_ptr.write_unaligned(msb_i16);

                    // SAFETY: u8x16 and i64x2 have the same layout
                    //  we need to convert cast it, because there is no shift impl for u8x16
                    let v_i64x2 = &mut v as *mut _ as *mut i64x2;
                    // shift each byte by one to the left (by shifting it as two i64)
                    *v_i64x2 = *v_i64x2 << 1;
                }
                col += 8;
            }
            row += 16;
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
unsafe fn load_bytes(b: &[u8], row: usize, col: usize, cols: usize) -> i8x16 {
    unsafe {
        // if we have sse2 we use _mm_setr_epi8 and transmute to convert bytes
        // faster than from impl
        #[cfg(target_feature = "sse2")]
        {
            let v = _mm_setr_epi8(
                *b.get_unchecked(inp(row, col, cols)) as i8,
                *b.get_unchecked(inp(row + 1, col, cols)) as i8,
                *b.get_unchecked(inp(row + 2, col, cols)) as i8,
                *b.get_unchecked(inp(row + 3, col, cols)) as i8,
                *b.get_unchecked(inp(row + 4, col, cols)) as i8,
                *b.get_unchecked(inp(row + 5, col, cols)) as i8,
                *b.get_unchecked(inp(row + 6, col, cols)) as i8,
                *b.get_unchecked(inp(row + 7, col, cols)) as i8,
                *b.get_unchecked(inp(row + 8, col, cols)) as i8,
                *b.get_unchecked(inp(row + 9, col, cols)) as i8,
                *b.get_unchecked(inp(row + 10, col, cols)) as i8,
                *b.get_unchecked(inp(row + 11, col, cols)) as i8,
                *b.get_unchecked(inp(row + 12, col, cols)) as i8,
                *b.get_unchecked(inp(row + 13, col, cols)) as i8,
                *b.get_unchecked(inp(row + 14, col, cols)) as i8,
                *b.get_unchecked(inp(row + 15, col, cols)) as i8,
            );
            transmute(v)
        }
        #[cfg(not(target_feature = "sse2"))]
        {
            let bytes = [
                *b.get_unchecked(inp(row, col, cols)) as i8,
                *b.get_unchecked(inp(row + 1, col, cols)) as i8,
                *b.get_unchecked(inp(row + 2, col, cols)) as i8,
                *b.get_unchecked(inp(row + 3, col, cols)) as i8,
                *b.get_unchecked(inp(row + 4, col, cols)) as i8,
                *b.get_unchecked(inp(row + 5, col, cols)) as i8,
                *b.get_unchecked(inp(row + 6, col, cols)) as i8,
                *b.get_unchecked(inp(row + 7, col, cols)) as i8,
                *b.get_unchecked(inp(row + 8, col, cols)) as i8,
                *b.get_unchecked(inp(row + 9, col, cols)) as i8,
                *b.get_unchecked(inp(row + 10, col, cols)) as i8,
                *b.get_unchecked(inp(row + 11, col, cols)) as i8,
                *b.get_unchecked(inp(row + 12, col, cols)) as i8,
                *b.get_unchecked(inp(row + 13, col, cols)) as i8,
                *b.get_unchecked(inp(row + 14, col, cols)) as i8,
                *b.get_unchecked(inp(row + 15, col, cols)) as i8,
            ];
            i8x16::from(bytes)
        }
    }
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use crate::transpose::transpose_bitmatrix;

    fn arbitrary_bitmat(max_row: usize, max_col: usize) -> BoxedStrategy<(Vec<u8>, usize, usize)> {
        (
            (16..max_row).prop_map(|row| row / 16 * 16),
            (16..max_col).prop_map(|col| col / 16 * 16),
        )
            .prop_flat_map(|(rows, cols)| {
                (vec![any::<u8>(); rows * cols / 8], Just(rows), Just(cols))
            })
            .boxed()
    }

    proptest! {
        #[cfg(not(miri))]
        #[test]
        fn test_double_transpose((v, rows, cols) in arbitrary_bitmat(16 * 30, 16 * 30)) {
            let transposed = transpose_bitmatrix(&v, rows);
            let double_transposed = transpose_bitmatrix(&transposed, cols);

            prop_assert_eq!(v, double_transposed);
        }
    }

    #[test]
    fn test_double_transpose_miri() {
        let rows = 32;
        let cols = 16;
        let v = vec![0; rows * cols];
        let transposed = transpose_bitmatrix(&v, rows);
        let double_transposed = transpose_bitmatrix(&transposed, cols);
        assert_eq!(v, double_transposed);
    }
}
