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

    let inp = |x: usize, y: usize| -> usize { x * cols / 8 + y / 8 };
    let out = |x: usize, y: usize| -> usize { y * rows / 8 + x / 8 };

    unsafe {
        let mut msbs = [0_u8; 4];
        let mut row: usize = 0;
        while row <= rows - 16 {
            let mut col = 0;
            while col < cols {
                // get col byte of row to row + 15
                let mut v = i8x16::from([
                    *input.get_unchecked(inp(row, col)) as i8,
                    *input.get_unchecked(inp(row + 1, col)) as i8,
                    *input.get_unchecked(inp(row + 2, col)) as i8,
                    *input.get_unchecked(inp(row + 3, col)) as i8,
                    *input.get_unchecked(inp(row + 4, col)) as i8,
                    *input.get_unchecked(inp(row + 5, col)) as i8,
                    *input.get_unchecked(inp(row + 6, col)) as i8,
                    *input.get_unchecked(inp(row + 7, col)) as i8,
                    *input.get_unchecked(inp(row + 8, col)) as i8,
                    *input.get_unchecked(inp(row + 9, col)) as i8,
                    *input.get_unchecked(inp(row + 10, col)) as i8,
                    *input.get_unchecked(inp(row + 11, col)) as i8,
                    *input.get_unchecked(inp(row + 12, col)) as i8,
                    *input.get_unchecked(inp(row + 13, col)) as i8,
                    *input.get_unchecked(inp(row + 14, col)) as i8,
                    *input.get_unchecked(inp(row + 15, col)) as i8,
                ]);
                // reverse iterator because we start writing the msb of each byte, then shift
                // left for i = 0, we write the previous lsb
                (0..8).rev().for_each(|i| {
                    // get msb of each byte
                    msbs = v.move_mask().to_le_bytes();
                    // dbg!(msbs);
                    // write msbs to output at transposed position
                    *output.get_unchecked_mut(out(row, col + i)) = msbs[0];
                    *output.get_unchecked_mut(out(row, col + i) + 1) = msbs[1];
                    // SAFETY: u8x16 and i64x2 have the same layout
                    //  we need to convert cast it, because there is no shift impl for u8x16
                    let v_i64x2 = &mut v as *mut _ as *mut i64x2;
                    // shift each byte by one to the left (by shifting it as two i64)
                    *v_i64x2 = *v_i64x2 << 1;
                });
                col += 8;
            }
            row += 16;
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
        #[test]
        fn test_double_transpose((v, rows, cols) in arbitrary_bitmat(16 * 30, 16 * 30)) {
            let transposed = transpose_bitmatrix(&v, rows);
            let double_transposed = transpose_bitmatrix(&transposed, cols);

            prop_assert_eq!(v, double_transposed);
        }
    }
}
