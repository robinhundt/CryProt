use std::ops::{BitAndAssign, BitXorAssign};

pub fn xor_inplace<T: Copy + BitXorAssign>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a ^= *b;
    });
}

pub fn and_inplace<T: Copy + BitAndAssign>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a &= *b;
    });
}

pub fn xor_inplace_elem<T: Copy + BitXorAssign>(a: &mut [T], b: T) {
    a.iter_mut().for_each(|a| {
        *a ^= b;
    });
}

pub fn and_inplace_elem<T: Copy + BitAndAssign>(a: &mut [T], b: T) {
    a.iter_mut().for_each(|a| {
        *a &= b;
    });
}

pub fn log2_ceil(val: usize) -> usize {
    let log2 = val.ilog2();
    if val > (1 << log2) {
        (log2 + 1) as usize
    } else {
        log2 as usize
    }
}
