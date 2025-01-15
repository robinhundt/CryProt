use std::{
    alloc::{alloc_zeroed, Layout},
    mem,
    ops::BitXorAssign,
};

use bytemuck::Zeroable;

pub fn xor_inplace<T: Copy + BitXorAssign>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a ^= *b;
    });
}

pub fn xor_inplace_elem<T: Copy + BitXorAssign>(a: &mut [T], b: T) {
    a.iter_mut().for_each(|a| {
        *a ^= b;
    });
}

/// Efficiently allocates a zeroed Vec<T> of provided len.
pub fn allocate_zeroed_vec<T: Zeroable>(len: usize) -> Vec<T> {
    unsafe {
        let size = len * mem::size_of::<T>();
        let align = mem::align_of::<T>();
        let layout = Layout::from_size_align(size, align).expect("len too large");
        let zeroed = alloc_zeroed(layout);
        // Safety (see https://doc.rust-lang.org/stable/std/vec/struct.Vec.html#method.from_raw_parts):
        // - zeroed ptr was allocated via global allocator
        // - zeroed was allocated with exact alignment of T
        // - size of T times capacity (len) is equal to size of allocation
        // - length values are initialized because of alloc_zeroed and T: Zeroable
        // - allocated size is less than isize::MAX ensured by Layout construction,
        //   otherwise panic
        Vec::from_raw_parts(zeroed as *mut T, len, len)
    }
}

#[cfg(test)]
mod tests {
    use super::allocate_zeroed_vec;
    use crate::Block;

    #[test]
    fn test_allocate_zeroed() {
        allocate_zeroed_vec::<Block>(25);
    }
}
