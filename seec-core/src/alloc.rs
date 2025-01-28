use std::{
    alloc::Layout,
    mem,
    ops::{Deref, DerefMut},
};

use bytemuck::Zeroable;

#[cfg(all(feature = "nightly", target_family = "unix"))]
pub mod thp_alloc;

#[cfg(all(feature = "nightly", target_family = "unix"))]
pub struct HugeVec<T>(Vec<T, thp_alloc::TransparentHugePagesAllocator>);

#[cfg(not(all(feature = "nightly", target_family = "unix")))]
pub struct HugeVec<T>(Vec<T>);

#[cfg(all(feature = "nightly", target_family = "unix"))]
impl<T: Zeroable> HugeVec<T> {
    pub fn zeroed(size: usize) -> HugeVec<T> {
        let v = {
            let mut v = Vec::with_capacity_in(size, thp_alloc::TransparentHugePagesAllocator);
            // SAFETY: T: Zeroable ensures that all-zeroes is a valid bit pattern for T.
            // TransparentHugePagesAllocator allocates zeroed memory.
            unsafe {
                v.set_len(size);
            }
            v
        };
        Self(v)
    }
}

#[cfg(not(all(feature = "nightly", target_family = "unix")))]
impl<T: Zeroable> HugeVec<T> {
    pub fn zeroed(size: usize) -> HugeVec<T> {
        Self(allocate_zeroed_vec(size))
    }
}

pub fn allocate_zeroed_vec<T: Zeroable>(len: usize) -> Vec<T> {
    unsafe {
        let size = len * mem::size_of::<T>();
        let align = mem::align_of::<T>();
        let layout = Layout::from_size_align(size, align).expect("len too large");
        let zeroed = std::alloc::alloc_zeroed(layout);
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

impl<T> Deref for HugeVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for HugeVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
