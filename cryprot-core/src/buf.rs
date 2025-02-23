//! Owned buffer abstraction trait for [`Vec`] and [`HugePageMemory`].
//!
//! The sealed [`Buf`] trait allows write code generic [`Vec`] or
//! [`HugePageMemory`]
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use bytemuck::Zeroable;

use crate::alloc::{HugePageMemory, allocate_zeroed_vec};

pub trait Buf<T>:
    Default + Debug + Deref<Target = [T]> + DerefMut + Send + Sync + 'static + private::Sealed
{
    /// The 'kind' of this Buf implementation. This is e.g. `Vec<E>` for `Vec<T>
    /// as Buf<T>`.
    ///
    /// This associated type can be used to create Bufs of the same kind, but
    /// with a different inner type.
    type BufKind<E>: Buf<E>
    where
        E: Zeroable + Clone + Default + Debug + Send + Sync + 'static;
    /// Create a new `Buf` of length `len` with all elements set to zero.
    ///
    /// Implementations of this directly allocate zeroed memory and do not write
    /// zeroes to the elements explicitly.
    fn zeroed(len: usize) -> Self;

    /// Capacity of the `Buf`.
    fn capacity(&self) -> usize;

    /// Sets the length of the buffer
    /// # Panic
    /// Panics if `len > self.capacity`.
    fn set_len(&mut self, new_len: usize);

    /// Grow the `Buf` to `new_size` and fill with zeroes.
    ///
    /// ```
    /// # use cryprot_core::buf::Buf;
    /// let mut v: Vec<u8> = Vec::zeroed(20);
    /// assert_eq!(20, v.len());
    /// v.grow_zeroed(40);
    /// assert_eq!(40, v.len());
    /// ```
    fn grow_zeroed(&mut self, new_size: usize);
}

impl<T: Zeroable + Clone + Default + Debug + Send + Sync + 'static> Buf<T> for Vec<T> {
    type BufKind<E>
        = Vec<E>
    where
        E: Zeroable + Clone + Default + Debug + Send + Sync + 'static;

    fn zeroed(len: usize) -> Self {
        allocate_zeroed_vec(len)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn set_len(&mut self, new_len: usize) {
        assert!(new_len <= self.capacity());
        // SAFETY:
        // new_len <= self.capacity
        // self[len..new_len] is initialized either because of Self::zeroed
        // or with data written to it.
        unsafe {
            self.set_len(new_len);
        }
    }

    fn grow_zeroed(&mut self, new_size: usize) {
        self.resize(new_size, T::zeroed());
    }
}

impl<T: Zeroable + Clone + Default + Debug + Send + Sync + 'static> Buf<T> for HugePageMemory<T> {
    type BufKind<E>
        = HugePageMemory<E>
    where
        E: Zeroable + Clone + Default + Debug + Send + Sync + 'static;

    fn zeroed(len: usize) -> Self {
        HugePageMemory::zeroed(len)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn set_len(&mut self, new_len: usize) {
        self.set_len(new_len);
    }

    fn grow_zeroed(&mut self, new_size: usize) {
        self.grow_zeroed(new_size);
    }
}

mod private {
    use crate::alloc::HugePageMemory;

    pub trait Sealed {}

    impl<T> Sealed for Vec<T> {}
    impl<T> Sealed for HugePageMemory<T> {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf() {
        let buf = Vec::<u8>::zeroed(1024);
        assert_eq!(buf.len(), 1024);
        assert!(buf.iter().all(|&x| x == 0));
    }
}
