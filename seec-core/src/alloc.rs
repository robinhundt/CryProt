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
}

impl<T> HugePageMemory<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> HugePageMemory<T> {
    pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
}

#[cfg(target_family = "unix")]
impl<T: Zeroable> HugePageMemory<T> {
    /// Allocate a buffer of `len` elements that is backed by transparent huge
    /// pages.
    pub fn zeroed(len: usize) -> Self {
        let layout = Self::layout(len);
        let padded_size = layout.size();
        let ptr = unsafe {
            // allocate memory using mmap
            let ptr = libc::mmap(
                ptr::null_mut(),
                padded_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                handle_alloc_error(layout)
            }
            // #[cfg(not(miri))]
            if libc::madvise(ptr, padded_size, libc::MADV_HUGEPAGE) != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(
                        // ENOMEM - Not enough memory/resources available
                        libc::ENOMEM
                        // EINVAL - Invalid arguments (shouldn't happen with our layout)
                        | libc::EINVAL) => {
                        libc::munmap(ptr, padded_size);
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

        Self { ptr, len }
    }
}

#[cfg(target_family = "unix")]
impl<T> HugePageMemory<T> {
    fn layout(len: usize) -> Layout {
        let size = len * mem::size_of::<T>();
        let align = mem::align_of::<T>().min(Self::HUGE_PAGE_SIZE);
        let layout = Layout::from_size_align(size, align).expect("alloc too large");
        layout.pad_to_align()
    }
}

#[cfg(target_family = "unix")]
impl<T> Drop for HugePageMemory<T> {
    fn drop(&mut self) {
        let layout = Self::layout(self.len);
        let padded_size = layout.size();
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), padded_size);
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

    fn deref(&self) -> &Self::Target {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> DerefMut for HugePageMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T> Default for HugePageMemory<T> {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
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
