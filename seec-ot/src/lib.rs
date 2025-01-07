use std::future::Future;

use bitvec::slice::BitSlice;
use seec_core::Block;

mod base;

pub trait RotSender {
    type Error;

    fn send(
        &mut self,
        count: usize,
    ) -> impl Future<Output = Result<Vec<[Block; 2]>, Self::Error>> + Send;
}

pub trait RotReceiver {
    type Error;

    fn receive(
        &mut self,
        choices: BitSlice,
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send;
}
