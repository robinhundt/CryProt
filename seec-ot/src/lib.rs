use std::future::Future;

use rand::{distributions, prelude::Distribution, rngs::StdRng, CryptoRng, Rng, SeedableRng};
use seec_core::{buf::Buf, Block};
use subtle::Choice;

pub mod base;
pub mod extension;
pub mod phase;
pub mod silent_ot;

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
            let mut ots = Vec::zeroed(count);
            self.send_into(&mut ots).await?;
            Ok(ots)
        }
    }

    /// Store OTs in the provided [`Buf`]fer.
    ///
    /// For large number of OTs, using
    /// [`HugePageMemory`](`seec_core::alloc::HugePageMemory`) can significantly
    /// improve performance on Linux systems.
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
            let mut ots = Vec::zeroed(choices.len());
            self.receive_into(choices, &mut ots).await?;
            Ok(ots)
        }
    }
}

/// Returns a random choice vector alongside OTs.
pub trait RandChoiceRotReceiver {
    type Error;

    fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<Vec<Choice>, Self::Error>> + Send;

    fn rand_choice_receive(
        &mut self,
        count: usize,
    ) -> impl Future<Output = Result<(Vec<Block>, Vec<Choice>), Self::Error>> + Send
    where
        Self: Send,
    {
        async move {
            let mut ots = Vec::zeroed(count);
            let choices = self.rand_choice_receive_into(&mut ots).await?;
            Ok((ots, choices))
        }
    }
}

impl<R: RotReceiver + Send> RandChoiceRotReceiver for R {
    type Error = R::Error;

    fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<Vec<Choice>, Self::Error>> + Send {
        async {
            let choices = random_choices(ots.len(), &mut StdRng::from_entropy());
            self.receive_into(&choices, ots).await?;
            Ok(choices)
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
