use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use bytemuck::Zeroable;

use crate::alloc::{allocate_zeroed_vec, HugePageMemory};

pub trait Buf<T>: Default + Debug + Deref<Target = [T]> + DerefMut + Send + Sync + 'static {
    fn zeroed(len: usize) -> Self;
}

impl<T: Zeroable + Default + Debug + Send + Sync + 'static> Buf<T> for Vec<T> {
    fn zeroed(len: usize) -> Self {
        allocate_zeroed_vec(len)
    }
}

impl<T: Zeroable + Default + Debug + Send + Sync + 'static> Buf<T> for HugePageMemory<T> {
    fn zeroed(len: usize) -> Self {
        HugePageMemory::zeroed(len)
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
