use std::{
    alloc::{handle_alloc_error, Layout},
    fmt::Debug,
    mem,
    ops::{Deref, DerefMut},
    ptr::{self, NonNull},
    slice,
};

use bytemuck::Zeroable;

/// An owned memory buffer that is allocated with transparent huge pages.
///
/// Using [`HugePageMemory::zeroed`], you can quickly allocate a buffer of
/// `len` elements of type `T` that is backed by transparent huge pages on Unix
/// systems. Note that the allocation might be larger that requested to align to
/// page boundaries. On non Unix systems, the memory will be allocated with the
/// global allocator.
pub struct HugePageMemory<T> {
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
}

pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

impl<T> HugePageMemory<T> {
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Sets the len of the HugePageMemory.
    /// # Panic
    /// Panics if `new_len > self.capacity()`
    #[inline]
    pub fn set_len(&mut self, new_len: usize) {
        assert!(new_len <= self.capacity());
        // SAFETY:
        // new_len <= self.capacity
        // self[len..new_len] is initialized either because of Self::zeroed
        // or with data written to it.
        #[allow(unused_unsafe)]
        unsafe {
            self.len = new_len;
        }
    }
}

#[cfg(target_family = "unix")]
impl<T: Zeroable> HugePageMemory<T> {
    /// Allocate a buffer of `len` elements that is backed by transparent huge
    /// pages.
    pub fn zeroed(len: usize) -> Self {
        let layout = Self::layout(len);
        let capacity = layout.size();
        let ptr = unsafe {
            // allocate memory using mmap
            let ptr = libc::mmap(
                ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                handle_alloc_error(layout)
            }
            #[cfg(not(miri))]
            if libc::madvise(ptr, capacity, libc::MADV_HUGEPAGE) != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(
                        // ENOMEM - Not enough memory/resources available
                        libc::ENOMEM
                        // EINVAL - Invalid arguments (shouldn't happen with our layout)
                        | libc::EINVAL) => {
                        libc::munmap(ptr, capacity);
                        handle_alloc_error(layout);
                    }
                    // Other errors (e.g., EACCES, EAGAIN)
                    _ => {
                        tracing::warn!("Failed to enable huge pages: {}", err);
                    }
                }
            }
            NonNull::new_unchecked(ptr.cast())
        };

        Self { ptr, len, capacity }
    }
}

impl<T: Zeroable + Clone> HugePageMemory<T> {
    /// Grows the HugePageMemory to at least `new_size` zeroed elements.
    pub fn grow_zeroed(&mut self, new_size: usize) {
        // If new size fits in current capacity, just update length
        if new_size <= self.capacity() {
            self.set_len(new_size);
            return;
        }

        #[cfg(target_os = "linux")]
        {
            self.grow_with_mremap(new_size);
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.grow_with_mmap(new_size);
        }
    }

    /// Grow implementation using mremap (Linux-specific)
    #[cfg(target_os = "linux")]
    fn grow_with_mremap(&mut self, new_size: usize) {
        // Calculate new layout
        let new_layout = Self::layout(new_size);
        let new_capacity = new_layout.size();

        let new_ptr = unsafe {
            let remapped_ptr = libc::mremap(
                self.ptr.as_ptr().cast(),
                self.capacity,
                new_capacity,
                libc::MREMAP_MAYMOVE,
            );

            if remapped_ptr == libc::MAP_FAILED {
                libc::munmap(self.ptr.as_ptr().cast(), self.capacity);
                handle_alloc_error(new_layout);
            }

            // Successfully remapped
            #[cfg(not(miri))]
            if libc::madvise(remapped_ptr, new_capacity, libc::MADV_HUGEPAGE) != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!("Failed to enable huge pages after mremap: {}", err);
            }

            NonNull::new_unchecked(remapped_ptr.cast())
        };

        // Update the struct with new pointer, capacity, and length
        self.ptr = new_ptr;
        self.capacity = new_capacity;
        self.set_len(new_size);
    }

    /// Fallback grow implementation using mmap
    #[allow(dead_code)]
    fn grow_with_mmap(&mut self, new_size: usize) {
        let mut new = Self::zeroed(new_size);
        new[..self.len()].clone_from_slice(self);
        *self = new;
    }
}

#[cfg(target_family = "unix")]
impl<T> HugePageMemory<T> {
    fn layout(len: usize) -> Layout {
        let size = len * mem::size_of::<T>();
        let align = mem::align_of::<T>().min(HUGE_PAGE_SIZE);
        let layout = Layout::from_size_align(size, align).expect("alloc too large");
        layout.pad_to_align()
    }
}

#[cfg(target_family = "unix")]
impl<T> Drop for HugePageMemory<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.capacity);
        }
    }
}

// Fallback implementation on non unix systems.
#[cfg(not(target_family = "unix"))]
impl<T: Zeroable> HugePageMemory<T> {
    pub fn zeroed(len: usize) -> Self {
        let v = allocate_zeroed_vec(len);
        assert_eq!(v.len(), v.capacity());
        let ptr = NonNull::new(v.leak().as_mut_ptr()).expect("not null");
        Self { ptr, len }
    }
}

#[cfg(not(target_family = "unix"))]
impl<T> Drop for HugePageMemory<T> {
    fn drop(&mut self) {
        unsafe { Vec::from_raw_parts(self.ptr.as_ptr(), self.len, self.len) };
    }
}

impl<T> Deref for HugePageMemory<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> DerefMut for HugePageMemory<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> Default for HugePageMemory<T> {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            capacity: 0,
        }
    }
}

impl<T: Debug> Debug for HugePageMemory<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

unsafe impl<T: Send> Send for HugePageMemory<T> {}
unsafe impl<T: Sync> Sync for HugePageMemory<T> {}

// Keep this function as it has less strict Bounds on T than Vec::zeroed.
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

#[cfg(test)]
mod tests {
    use super::{HugePageMemory, HUGE_PAGE_SIZE};

    #[test]
    fn test_huge_page_memory() {
        let mut mem = HugePageMemory::<u8>::zeroed(HUGE_PAGE_SIZE + HUGE_PAGE_SIZE / 2);
        #[cfg(not(miri))] // miri is too slow for this
        for b in mem.iter() {
            assert_eq!(0, *b);
        }
        assert!(mem[0] == 0);
        assert!(mem[mem.len() - 1] == 0);
        mem[42] = 5;
        mem.set_len(HUGE_PAGE_SIZE);
        assert_eq!(HUGE_PAGE_SIZE, mem.len());
    }

    #[test]
    #[should_panic]
    fn test_set_len_panics() {
        let mut mem = HugePageMemory::<u8>::zeroed(HUGE_PAGE_SIZE);
        mem.set_len(HUGE_PAGE_SIZE + 1);
    }

    #[test]
    fn test_grow() {
        let mut mem = HugePageMemory::<u8>::zeroed(HUGE_PAGE_SIZE);
        assert_eq!(0, mem[0]);
        mem[0] = 1;
        mem.grow_zeroed(2 * HUGE_PAGE_SIZE);
        assert_eq!(2 * HUGE_PAGE_SIZE, mem.len());
        assert_eq!(2 * HUGE_PAGE_SIZE, mem.capacity());
        assert_eq!(1, mem[0]);
        assert_eq!(0, mem[HUGE_PAGE_SIZE + 1]);
    }
}
