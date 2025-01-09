use std::future::Future;

use rand::{distributions, prelude::Distribution, CryptoRng, Rng};
use seec_core::Block;
use subtle::Choice;

pub mod base;
pub mod extension;

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
        choices: &[Choice],
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send;
}

pub fn random_choices<RNG: Rng + CryptoRng>(count: usize, rng: &mut RNG) -> Vec<Choice> {
    let uniform = distributions::Uniform::new(0, 2);
    uniform
        .sample_iter(rng)
        .take(count)
        .map(|v| Choice::from(v))
        .collect()
}
