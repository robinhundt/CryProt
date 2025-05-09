//! Linear code implementations for Silent OT.
//!
//! This crate currently only implements the expand-convolute code of [[RRT23](https://eprint.iacr.org/2023/882)] in [`ex_conv`].
use std::ops::{BitXor, BitXorAssign};

use bytemuck::Pod;
use cryprot_core::Block;

pub mod ex_conv;

pub use ex_conv::{ExConvCode, ExConvCodeConfig};

/// Sealed trait implemented for [`Block`] and [`u8`].
pub trait Coeff:
    BitXor<Output = Self> + BitXorAssign + Copy + Clone + Pod + Sized + private::Sealed
{
    const ZERO: Self;
}

impl Coeff for Block {
    const ZERO: Self = Block::ZERO;
}

impl Coeff for u8 {
    const ZERO: Self = 0;
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::Block {}
    impl Sealed for u8 {}
}
