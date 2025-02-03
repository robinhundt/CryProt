use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use bytemuck::Zeroable;

use crate::alloc::{allocate_zeroed_vec, HugePageMemory};

pub trait Buf<T>: Default + Debug + Deref<Target = [T]> + DerefMut + Send + Sync + 'static {
    fn zeroed(len: usize) -> Self;

    fn capacity(&self) -> usize;

    /// Sets the length of the buffer
    /// # Panic
    /// Panics if `len > self.capacity`.
    fn set_len(&mut self, new_len: usize);
}

impl<T: Zeroable + Default + Debug + Send + Sync + 'static> Buf<T> for Vec<T> {
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
}

impl<T: Zeroable + Default + Debug + Send + Sync + 'static> Buf<T> for HugePageMemory<T> {
    fn zeroed(len: usize) -> Self {
        HugePageMemory::zeroed(len)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn set_len(&mut self, new_len: usize) {
        self.set_len(new_len);
    }
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
