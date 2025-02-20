use std::{fmt::Debug, future::Future};

use cryprot_core::{buf::Buf, Block};
use cryprot_net::Connection;
use rand::{distributions, prelude::Distribution, rngs::StdRng, CryptoRng, Rng, SeedableRng};
use subtle::Choice;

pub mod adapter;
pub mod base;
pub mod extension;
pub mod noisy_vole;
pub mod phase;
pub mod silent_ot;

pub trait Connected {
    fn connection(&mut self) -> &mut Connection;
}

pub trait RotSender: Connected + Send {
    type Error;

    fn send(
        &mut self,
        count: usize,
    ) -> impl Future<Output = Result<Vec<[Block; 2]>, Self::Error>> + Send {
        async move {
            let mut ots = Vec::zeroed(count);
            self.send_into(&mut ots).await?;
            Ok(ots)
        }
    }

    /// Store OTs in the provided [`Buf`]fer.
    ///
    /// For large number of OTs, using
    /// [`HugePageMemory`](`cryprot_core::alloc::HugePageMemory`) can
    /// significantly improve performance on Linux systems.
    fn send_into(
        &mut self,
        ots: &mut impl Buf<[Block; 2]>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait RotReceiver: Connected + Send {
    type Error;

    fn receive_into(
        &mut self,
        choices: &[Choice],
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn receive(
        &mut self,
        choices: &[Choice],
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send {
        async {
            let mut ots = Vec::zeroed(choices.len());
            self.receive_into(choices, &mut ots).await?;
            Ok(ots)
        }
    }
}

/// Marker trait for R-OT Senders that are paired with a random choice receiver.
pub trait RandChoiceRotSender {}

/// Returns a random choice vector alongside OTs.
pub trait RandChoiceRotReceiver: Connected + Send {
    type Error;

    fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<Vec<Choice>, Self::Error>> + Send;

    fn rand_choice_receive(
        &mut self,
        count: usize,
    ) -> impl Future<Output = Result<(Vec<Block>, Vec<Choice>), Self::Error>> + Send {
        async move {
            let mut ots = Vec::zeroed(count);
            let choices = self.rand_choice_receive_into(&mut ots).await?;
            Ok((ots, choices))
        }
    }
}

impl<R: RotReceiver> RandChoiceRotReceiver for R {
    type Error = R::Error;

    async fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Self::Error> {
        let choices = random_choices(ots.len(), &mut StdRng::from_entropy());
        self.receive_into(&choices, ots).await?;
        Ok(choices)
    }
}

/// Marker trait for OT implementations secure against semi-honest adversaries.
pub trait SemiHonest {}

/// Marker trait for OT implementations secure against malicious adversaries.
pub trait Malicious: SemiHonest {}

/// Used to abstract over [`SemiHonestMarker`] or [`MaliciousMarker`]
pub trait Security: Send + Sync + Debug + Copy + Clone + private::Sealed {
    const MALICIOUS_SECURITY: bool;
}

/// Used as a marker type for semi-honest security OT implementation.
#[derive(Copy, Clone, Debug)]
pub struct SemiHonestMarker;

impl Security for SemiHonestMarker {
    const MALICIOUS_SECURITY: bool = false;
}

/// Used as a marker type for malicious security OT implementation.
#[derive(Copy, Clone, Debug)]
pub struct MaliciousMarker;

impl Security for MaliciousMarker {
    const MALICIOUS_SECURITY: bool = true;
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::SemiHonestMarker {}

    impl Sealed for super::MaliciousMarker {}
}

pub fn random_choices<RNG: Rng + CryptoRng>(count: usize, rng: &mut RNG) -> Vec<Choice> {
    let uniform = distributions::Uniform::new(0, 2);
    uniform
        .sample_iter(rng)
        .take(count)
        .map(Choice::from)
        .collect()
}
