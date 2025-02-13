use std::ops::{BitXor, BitXorAssign};

use bytemuck::Pod;
use cryprot_core::Block;

pub mod ex_conv;

pub trait GF2ops: BitXor<Output = Self> + BitXorAssign + Copy + Clone + Pod + Sized {
    const ZERO: Self;
}

impl GF2ops for Block {
    const ZERO: Self = Block::ZERO;
}

impl GF2ops for u8 {
    const ZERO: Self = 0;
}
