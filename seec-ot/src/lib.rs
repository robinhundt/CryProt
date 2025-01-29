use std::future::Future;

use rand::{distributions, prelude::Distribution, CryptoRng, Rng};
use seec_core::{alloc::allocate_zeroed_vec, buf::Buf, Block};
use subtle::Choice;

pub mod base;
pub mod extension;
pub mod phase;

pub trait RotSender {
    type Error;

    fn send(
        &mut self,
        count: usize,
    ) -> impl Future<Output = Result<Vec<[Block; 2]>, Self::Error>> + Send
    where
        Self: Send,
    {
        async move {
            let mut ots = allocate_zeroed_vec(count);
            self.send_into(&mut ots).await?;
            Ok(ots)
        }
    }

    fn send_into(
        &mut self,
        ots: &mut impl Buf<[Block; 2]>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait RotReceiver {
    type Error;

    fn receive_into(
        &mut self,
        choices: &[Choice],
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn receive(
        &mut self,
        choices: &[Choice],
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send
    where
        Self: Send,
    {
        async {
            let mut ots = allocate_zeroed_vec(choices.len());
            self.receive_into(choices, &mut ots).await?;
            Ok(ots)
        }
    }
}

pub fn random_choices<RNG: Rng + CryptoRng>(count: usize, rng: &mut RNG) -> Vec<Choice> {
    let uniform = distributions::Uniform::new(0, 2);
    uniform
        .sample_iter(rng)
        .take(count)
        .map(Choice::from)
        .collect()
}
