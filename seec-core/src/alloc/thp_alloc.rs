use std::{
    alloc::{AllocError, Allocator},
    ptr::{self, NonNull},
};

use bytemuck::Zeroable;

#[derive(Debug)]
pub struct TransparentHugePagesAllocator;
const HUGE_PAGE_SIZE: usize = 2 * 1024;

unsafe impl Allocator for TransparentHugePagesAllocator {
    fn allocate(
        &self,
        mut layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, AllocError> {
        layout = layout.align_to(HUGE_PAGE_SIZE).map_err(|_| AllocError)?;
        layout = layout.pad_to_align();
        let size = layout.size();
        unsafe {
            let ptr = libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(AllocError);
            }
            #[cfg(not(miri))]
            if libc::madvise(ptr, size, libc::MADV_HUGEPAGE) != 0 {
                libc::munmap(ptr, size);
                return Err(AllocError);
            }
            let slice = ptr::slice_from_raw_parts_mut(ptr.cast(), size);
            Ok(NonNull::new_unchecked(slice))
        }
    }

    fn allocate_zeroed(&self, layout: std::alloc::Layout) -> Result<NonNull<[u8]>, AllocError> {
        // SAFETY: self allocate already returns zero initialized memory
        self.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, mut layout: std::alloc::Layout) {
        layout = layout.align_to(HUGE_PAGE_SIZE).expect("allocate align_to worked");
        layout = layout.pad_to_align();
        unsafe {
            libc::munmap(ptr.as_ptr().cast(), layout.size());
        }
    }
}

pub fn allocate_zeroed_with_huge_pages<T: Zeroable>(len: usize) -> Vec<T, TransparentHugePagesAllocator> {
    let mut v = Vec::with_capacity_in(len, TransparentHugePagesAllocator);
    // SAFETY: TransparentHugePagesAllocator::alloc allocates zeroed memory
    unsafe {
        v.set_len(len);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::{TransparentHugePagesAllocator, HUGE_PAGE_SIZE};

    #[test]
    fn test_huge_page_alloc() {
        let size = 10 * HUGE_PAGE_SIZE;
        let mut v: Vec<u8, _> = Vec::with_capacity_in(size, TransparentHugePagesAllocator);
        v.push(1);
    }

    #[test]
    fn test_huge_page_zeroed() {
        let mut v: Vec<u8, _> = Vec::with_capacity_in(HUGE_PAGE_SIZE, TransparentHugePagesAllocator);
        unsafe {
            // allocator returns zero initialized memory
            v.set_len(HUGE_PAGE_SIZE);
        }
        for el in v {
            assert_eq!(0, el);
        }
    }
}