#![warn(clippy::unwrap_used)]
//! CryProt-OT implements several [oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer) protocols.
//!
//! - base OT: "Simplest OT" [[CO15](https://eprint.iacr.org/2015/267)]
//! - semi-honest OT extension: optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)]
//!   protocol
//! - malicious OT extension: optimized [[KOS15](https://eprint.iacr.org/2015/546.pdf)]
//!   protocol
//! - silent OT extension: [[BCG+19](https://eprint.iacr.org/2019/1159)] silent OT
//!   using [[RRT23](https://eprint.iacr.org/2023/882)] code (semi-honest and malicious
//!   with [[YWL+20](https://dl.acm.org/doi/pdf/10.1145/3372297.3417276)]
//!   consistency check)
//!
//! This library is heavily inspired by and in parts a port of the C++ [libOTe](https://github.com/osu-crypto/libOTe) library.
//!
//! ## Benchmarks
//! We continously run the benchmark suite in CI witht the results publicly
//! available on [bencher.dev](https://bencher.dev/perf/cryprot/plots). The raw criterion output, including throughput is
//! available in the logs of the [bench workflow](https://github.com/robinhundt/CryProt/actions/workflows/bench.yml)
//! (latest run > benchmarks job > Run Benchmarks step).
//!
//! ## OT Extension Benchmarks
//! Following are benchmark numbers for several OT protocols on a 4-core VM
//! running on an AMD EPYC 9454P. For up to date benchmarks view the links in
//! the benchmarks section. Each OT sender/receiver uses one worker thread and
//! number of cores many background threads for communication (which by default
//! is also encrypted as part of QUIC).
//!
//! | Benchmark                                         | Mean Throughput (million OT/s) |
//! |--------------------------------------------------|--------------------------|
//! | Semi-honest R-OT ext. (2^24 R-OTs)       | 51.539                   |
//! | Malicious R-OT ext. (2^24 R-OTs)         | 33.663                   |
//! | Semi-Honest Silent C-OT ext. (2^21 C-OTs)          | 4.2306                   |
//! | Semi-Honest Silent R-OT ext. (2^21 R-OTs)              | 9.5426                   |
//! | Malicious Silent R-OT ext. (2^21 R-OTs)    | 7.4180                   |
//!
//! Silent OT will perform faster for smaller numbers of OTs at slightly
//! increased communication.
//!
//! Our OT implementations should be on par or faster than those in libOTe. In
//! the future we want to benchmark libOTe on the same hardware for a fair
//! comparison.
//!
//! **Base OT Benchmark:**
//!
//! | Benchmark      | Mean Time (ms) |
//! |---------------|---------------|
//! | 128 base R-OTs   | 28.001        |

use std::{fmt::Debug, future::Future};

use cryprot_core::{Block, buf::Buf};
use cryprot_net::Connection;
use rand::{CryptoRng, Rng, distr, prelude::Distribution, rngs::StdRng};
use subtle::Choice;

pub mod adapter;
pub mod base;
pub mod extension;
pub mod noisy_vole;
pub mod phase;
pub mod silent_ot;

/// Trait for OT receivers/senders which hold a [`Connection`].
pub trait Connected {
    fn connection(&mut self) -> &mut Connection;
}

impl<C: Connected> Connected for &mut C {
    fn connection(&mut self) -> &mut Connection {
        (*self).connection()
    }
}

/// A random OT sender.
pub trait RotSender: Connected + Send {
    /// The error type returned by send operations.
    type Error;

    /// Send `count` many random OTs.
    ///
    /// For better performance, use [RotSender::send_into] with an existing
    /// [`Buf`].
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
    /// Note that implementations might temporarily take ownership of the
    /// [`Buf`] pointed to by `ots`. If the future returned by this method is
    /// dropped befire completion, `ots` might point at an empty `Buf`.
    ///
    /// For large number of OTs, using
    /// [`HugePageMemory`](`cryprot_core::alloc::HugePageMemory`) can
    /// significantly improve performance on Linux systems.
    fn send_into(
        &mut self,
        ots: &mut impl Buf<[Block; 2]>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A random OT receiver.
pub trait RotReceiver: Connected + Send {
    /// The error type returned by receive operations.
    type Error;

    /// Receive `choices.len()` many random OTs.
    ///
    /// For better performance, use [RotReceiver::receive_into] with an existing
    /// [`Buf`].
    fn receive(
        &mut self,
        choices: &[Choice],
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send {
        async {
            let mut ots = Vec::zeroed(choices.len());
            self.receive_into(&mut ots, choices).await?;
            Ok(ots)
        }
    }

    /// Store OTs in the provided [`Buf`]fer.
    ///
    /// Note that implementations might temporarily take ownership of the
    /// [`Buf`] pointed to by `ots`. If the future returned by this method is
    /// dropped befire completion, `ots` might point at an empty `Buf`.
    ///
    /// For large number of OTs, using
    /// [`HugePageMemory`](`cryprot_core::alloc::HugePageMemory`) can
    /// significantly improve performance on Linux systems.
    fn receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
        choices: &[Choice],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<S: RotSender> RotSender for &mut S {
    type Error = S::Error;

    fn send_into(
        &mut self,
        ots: &mut impl Buf<[Block; 2]>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        (*self).send_into(ots)
    }
}

impl<R: RotReceiver> RotReceiver for &mut R {
    type Error = R::Error;

    fn receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
        choices: &[Choice],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        (*self).receive_into(ots, choices)
    }
}

/// Marker trait for R-OT Senders that are paired with a random choice receiver.
pub trait RandChoiceRotSender {}

/// Returns a random choice vector alongside OTs.
pub trait RandChoiceRotReceiver: Connected + Send {
    type Error;

    /// Receive `count` many random OTs alongside their respective choices.
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

    /// Receive `ots.len()` many random OTs, stored into the buffer pointed to
    /// by `ots` and returns the corresponding choices.
    fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> impl Future<Output = Result<Vec<Choice>, Self::Error>> + Send;
}

/// Adapt any [`RotReceiver`] into a [`RandChoiceRotReceiver`] by securely
/// sampling the random choices using [`random_choices`].
impl<R: RotReceiver> RandChoiceRotReceiver for R {
    type Error = R::Error;

    async fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Self::Error> {
        let choices = random_choices(ots.len(), &mut rand::make_rng::<StdRng>());
        self.receive_into(ots, &choices).await?;
        Ok(choices)
    }
}

/// Correlated OT sender (C-OT).
pub trait CotSender: Connected + Send {
    type Error;

    /// Random OTs correlated by the `correlation`` function..
    ///
    /// The correlation function is passed the index of a C-OT and must output
    /// the correlation for this C-OT.
    fn correlated_send<F>(
        &mut self,
        count: usize,
        correlation: F,
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send
    where
        F: FnMut(usize) -> Block + Send,
    {
        async move {
            let mut ots = Vec::zeroed(count);
            self.correlated_send_into(&mut ots, correlation).await?;
            Ok(ots)
        }
    }

    fn correlated_send_into<B, F>(
        &mut self,
        ots: &mut B,
        correlation: F,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        B: Buf<Block>,
        F: FnMut(usize) -> Block + Send;
}

pub trait CotReceiver: Connected + Send {
    type Error;

    fn correlated_receive(
        &mut self,
        choices: &[Choice],
    ) -> impl Future<Output = Result<Vec<Block>, Self::Error>> + Send {
        async {
            let mut ots = Vec::zeroed(choices.len());
            self.correlated_receive_into(&mut ots, choices).await?;
            Ok(ots)
        }
    }

    fn correlated_receive_into<B>(
        &mut self,
        ots: &mut B,
        choices: &[Choice],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        B: Buf<Block>;
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

/// Sample `count` many [`Choice`]es using the provided rng.
pub fn random_choices<RNG: Rng + CryptoRng>(count: usize, rng: &mut RNG) -> Vec<Choice> {
    let uniform = distr::Uniform::new(0, 2).expect("correct range");
    uniform
        .sample_iter(rng)
        .take(count)
        .map(Choice::from)
        .collect()
}
