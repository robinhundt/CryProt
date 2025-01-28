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
