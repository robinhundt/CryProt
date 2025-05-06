//! Fast OT extension using optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)] (semi-honest)
//! or [[KOS15](https://eprint.iacr.org/2015/546.pdf)] (malicious) protocol.
//!
//! The protocols are optimized for the availability of `aes` and `avx2` target
//! features for the semi-honest protocol and additionally `pclmulqdq` for the
//! malicious protocol.
//!
//! ## Batching
//! The protocols automatically compute the OTs in batches to increase
//! throughput. The [`DEFAULT_OT_BATCH_SIZE`] has been chosen to maximise
//! throughput in very low latency settings for large numbers of OTs.
//! The batch size can changed using the corresponding methods on the sender and
//! receiver (e.g. [`OtExtensionSender::with_batch_size`]).
use std::{io, iter, marker::PhantomData, mem, panic::resume_unwind, task::Poll};

use bytemuck::cast_slice_mut;
use cryprot_core::{
    Block,
    aes_hash::FIXED_KEY_HASH,
    aes_rng::AesRng,
    alloc::allocate_zeroed_vec,
    buf::Buf,
    tokio_rayon::spawn_compute,
    transpose::transpose_bitmatrix,
    utils::{and_inplace_elem, xor_inplace},
};
use cryprot_net::{Connection, ConnectionError};
use futures::{FutureExt, SinkExt, StreamExt, future::poll_fn};
use rand::{Rng, RngCore, SeedableRng, distr::StandardUniform, rngs::StdRng};
use subtle::{Choice, ConditionallySelectable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Level;

use crate::{
    Connected, CotReceiver, CotSender, Malicious, MaliciousMarker, RotReceiver, RotSender,
    Security, SemiHonest, SemiHonestMarker,
    adapter::CorrelatedFromRandom,
    base::{self, SimplestOt},
    phase, random_choices,
};

pub const BASE_OT_COUNT: usize = 128;

pub const DEFAULT_OT_BATCH_SIZE: usize = 2_usize.pow(16);

/// OT extension sender generic over its [`Security`] level.
pub struct OtExtensionSender<S: Security> {
    rng: StdRng,
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<AesRng>,
    base_choices: Vec<Choice>,
    delta: Option<Block>,
    batch_size: usize,
    security: PhantomData<S>,
}

/// OT extension receiver generic over its [`Security`] level.
pub struct OtExtensionReceiver<S: Security> {
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<[AesRng; 2]>,
    batch_size: usize,
    security: PhantomData<S>,
    rng: StdRng,
}

/// SemiHonest OT extension sender alias.
pub type SemiHonestOtExtensionSender = OtExtensionSender<SemiHonestMarker>;
/// SemiHonest OT extension receiver alias.
pub type SemiHonestOtExtensionReceiver = OtExtensionReceiver<SemiHonestMarker>;

/// Malicious OT extension sender alias.
pub type MaliciousOtExtensionSender = OtExtensionSender<MaliciousMarker>;
/// Malicious OT extension receiver alias.
pub type MaliciousOtExtensionReceiver = OtExtensionReceiver<MaliciousMarker>;

/// Error type returned by the OT extension protocols.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("unable to compute base OTs")]
    BaseOT(#[from] base::Error),
    #[error("connection error to peer")]
    Connection(#[from] ConnectionError),
    #[error("error in sending/receiving data")]
    Communication(#[from] io::Error),
    #[error("connection closed by peer")]
    UnexcpectedClose,
    /// Only possible for malicious variant.
    #[error("Commitment does not match seed")]
    WrongCommitment,
    /// Only possible for malicious variant.
    #[error("malicious check failed")]
    MaliciousCheck,
    #[doc(hidden)]
    #[error("async task is dropped. This error should not be observable.")]
    AsyncTaskDropped,
}

impl<S: Security> OtExtensionSender<S> {
    /// Create a new sender for the given [`Connection`].
    pub fn new(conn: Connection) -> Self {
        Self::new_with_rng(conn, StdRng::from_os_rng())
    }

    /// Create a new sender for the given [`Connection`] and [`StdRng`].
    ///
    /// For an rng seeded with a fixed seed, the output is deterministic.
    pub fn new_with_rng(mut conn: Connection, mut rng: StdRng) -> Self {
        let base_ot = SimplestOt::new_with_rng(conn.sub_connection(), StdRng::from_rng(&mut rng));
        Self {
            rng,
            base_ot,
            conn,
            base_rngs: vec![],
            base_choices: vec![],
            delta: None,
            batch_size: DEFAULT_OT_BATCH_SIZE,
            security: PhantomData,
        }
    }

    /// Set the OT batch size for the sender.
    ///
    /// If the sender batch size is changed, the receiver's must also be changed
    /// (see [`OtExtensionReceiver::with_batch_size`]).
    /// Note that [`OtExtensionSender::send`] methods will fail if `count %
    /// self.batch_size()` is not divisable by 128.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// The currently configured OT batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Returns true if base OTs have been performed. Subsequent calls to send
    /// will not perform base OTs again.
    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    /// Perform base OTs for later extension. Subsequent calls to send
    /// will not perform base OTs again.
    pub async fn do_base_ots(&mut self) -> Result<(), Error> {
        let base_choices = random_choices(BASE_OT_COUNT, &mut self.rng);
        let base_ots = self.base_ot.receive(&base_choices).await?;
        self.base_rngs = base_ots.into_iter().map(AesRng::from_seed).collect();
        self.delta = Some(Block::from_choices(&base_choices));
        self.base_choices = base_choices;
        Ok(())
    }
}

impl<S: Security> Connected for OtExtensionSender<S> {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl SemiHonest for OtExtensionSender<SemiHonestMarker> {}
/// A maliciously secure sender also offers semi-honest security at decreased
/// performance.
impl SemiHonest for OtExtensionSender<MaliciousMarker> {}

impl Malicious for OtExtensionSender<MaliciousMarker> {}

impl<S: Security> RotSender for OtExtensionSender<S> {
    type Error = Error;

    /// Sender part of OT extension.
    ///
    /// # Panics
    /// - If `count` is not divisable by 128.
    /// - If `count % self.batch_size()` is not divisable by 128.
    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::OT_EXTENSION))]
    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        let count = ots.len();
        assert_eq!(0, count % 128, "count must be multiple of 128");
        let batch_size = self.batch_size();
        let batches = count / batch_size;
        let batch_size_remainder = count % batch_size;
        let num_extra = (S::MALICIOUS_SECURITY as usize) * 128;

        assert_eq!(
            0,
            batch_size_remainder % 128,
            "count % batch_size must be multiple of 128"
        );

        let batch_sizes = iter::repeat(batch_size)
            .take(batches)
            .chain((batch_size_remainder != 0).then_some(batch_size_remainder));

        if !self.has_base_ots() {
            self.do_base_ots().await?;
        }

        let delta = self.delta.expect("base OTs are done");
        let mut sub_conn = self.conn.sub_connection();

        // channel for communication between async task and compute thread
        let (ch_s, ch_r) = std::sync::mpsc::channel::<Vec<Block>>();
        let (kos_ch_s, mut kos_ch_r_task) = tokio::sync::mpsc::unbounded_channel::<Block>();
        let (kos_ch_s_task, kos_ch_r) = std::sync::mpsc::channel::<Vec<Block>>();
        // take these to move them into compute thread, will be returned via ret channel
        let mut base_rngs = mem::take(&mut self.base_rngs);
        let base_choices = mem::take(&mut self.base_choices);
        let batch_sizes_th = batch_sizes.clone();
        let owned_ots = mem::take(ots);
        let mut rng = StdRng::from_rng(&mut self.rng);

        // spawn compute thread for CPU intensive work. This way we increase throughput
        // and don't risk of blocking tokio worker threads
        let jh = spawn_compute(move || {
            let mut ots = owned_ots;
            let mut extra_messages: Vec<[Block; 2]> = Vec::zeroed(num_extra);
            let mut transposed = Vec::zeroed(batch_size);
            let mut owned_v_mat: Vec<Block> = if S::MALICIOUS_SECURITY {
                Vec::zeroed(ots.len())
            } else {
                vec![]
            };
            let mut extra_v_mat = vec![Block::ZERO; num_extra];

            for (ots, batch_sizes, extra) in [
                (
                    &mut ots[..],
                    &mut batch_sizes_th.clone() as &mut dyn Iterator<Item = _>,
                    false,
                ),
                (&mut extra_messages[..], &mut iter::once(num_extra), true),
            ] {
                // to increase throughput, we divide the `count` many OTs into batches of size
                // self.batch_size(). Crucially, this allows us to do the transpose
                // and hash step while not having received the complete data from the
                // OtExtensionReceiver.
                for (chunk_idx, (ot_batch, curr_batch_size)) in
                    ots.chunks_mut(batch_size).zip(batch_sizes).enumerate()
                {
                    let v_mat = if S::MALICIOUS_SECURITY {
                        if extra {
                            &mut extra_v_mat
                        } else {
                            let offset = chunk_idx * batch_size;
                            &mut owned_v_mat[offset..offset + curr_batch_size]
                        }
                    } else {
                        // we temporarily use the output OT buffer to hold the current chunk of the
                        // V matrix which we XOR with our received row or 0
                        // and then transpose into `transposed`
                        cast_slice_mut(&mut ot_batch[..curr_batch_size / 2])
                    };
                    let v_mat = cast_slice_mut(v_mat);

                    let cols_byte_batch = curr_batch_size / 8;
                    let row_iter = v_mat.chunks_exact_mut(cols_byte_batch);

                    for ((v_row, base_rng), base_choice) in
                        row_iter.zip(&mut base_rngs).zip(&base_choices)
                    {
                        base_rng.fill_bytes(v_row);
                        let mut recv_row = ch_r.recv()?;
                        // constant time version of
                        // if !base_choice {
                        //   v_row ^= recv_row;
                        // }
                        let choice_mask =
                            Block::conditional_select(&Block::ZERO, &Block::ONES, *base_choice);
                        // if choice_mask == 0, we zero out recv_row
                        // if choice_mask == 1, recv_row is not changed
                        and_inplace_elem(&mut recv_row, choice_mask);
                        let v_row = bytemuck::cast_slice_mut(v_row);
                        // if choice_mask == 0, v_row = v_row ^ 000000..
                        // if choice_mask == 1, v_row = v_row ^ recv_row
                        xor_inplace(v_row, &recv_row);
                    }
                    {
                        let transposed = bytemuck::cast_slice_mut(&mut transposed);
                        transpose_bitmatrix(v_mat, &mut transposed[..v_mat.len()], BASE_OT_COUNT);
                    }

                    for (v, ots) in transposed.iter().zip(ot_batch.iter_mut()) {
                        *ots = [*v, *v ^ delta]
                    }

                    if S::MALICIOUS_SECURITY {
                        FIXED_KEY_HASH.tccr_hash_slice_mut(
                            bytemuck::must_cast_slice_mut(ot_batch),
                            |i| {
                                // use batch_size here, which is the batch_size of all batches
                                // except potentially the last. If we use curr_batch_size, our
                                // offset would be wrong for the last batch if curr_batch_size <
                                // batch_size
                                Block::from(chunk_idx * batch_size + (i / 2))
                            },
                        );
                    } else {
                        FIXED_KEY_HASH.cr_hash_slice_mut(bytemuck::must_cast_slice_mut(ot_batch));
                    }
                }
            }

            if S::MALICIOUS_SECURITY {
                let seed: Block = rng.random();
                kos_ch_s.send(seed)?;
                let rng = AesRng::from_seed(seed);

                let mut q1 = extra_v_mat;
                let mut q2 = vec![Block::ZERO; BASE_OT_COUNT];

                let owned_v_mat_ref = &owned_v_mat;

                let challenges: Vec<Block> = rng
                    .sample_iter(StandardUniform)
                    .take(ots.len() / BASE_OT_COUNT)
                    .collect();

                let block_batch_size = batch_size / BASE_OT_COUNT;

                let challenge_iter =
                    batch_sizes_th
                        .clone()
                        .enumerate()
                        .flat_map(|(batch, curr_batch_size)| {
                            challenges[batch * block_batch_size
                                ..batch * block_batch_size + curr_batch_size / BASE_OT_COUNT]
                                .iter()
                                .cycle()
                                .take(curr_batch_size)
                        });

                let q_idx_iter = batch_sizes_th.flat_map(|curr_batch_size| {
                    (0..BASE_OT_COUNT).flat_map(move |t_idx| {
                        iter::repeat_n(t_idx, curr_batch_size / BASE_OT_COUNT)
                    })
                });

                for ((v, s), q_idx) in owned_v_mat_ref.iter().zip(challenge_iter).zip(q_idx_iter) {
                    let (qi, qi2) = v.clmul(&s);
                    q1[q_idx] ^= qi;
                    q2[q_idx] ^= qi2;
                }

                for (q1i, q2i) in q1.iter_mut().zip(&q2) {
                    *q1i = Block::gf_reduce(q1i, q2i);
                }
                let mut u = kos_ch_r.recv().unwrap();
                let received_x = u.pop().unwrap();
                for ((received_t, base_choice), q1i) in u.iter().zip(&base_choices).zip(&q1) {
                    let tt =
                        Block::conditional_select(&Block::ZERO, &received_x, *base_choice) ^ *q1i;
                    if tt != *received_t {
                        return Err(Error::MaliciousCheck);
                    }
                }
            }

            Ok::<_, Error>((ots, base_rngs, base_choices))
        });

        let (_, mut recv) = sub_conn.byte_stream().await?;

        for batch_size in batch_sizes.chain((num_extra != 0).then_some(num_extra)) {
            for _ in 0..BASE_OT_COUNT {
                let mut recv_row = allocate_zeroed_vec(batch_size / Block::BITS);
                recv.read_exact(bytemuck::cast_slice_mut(&mut recv_row))
                    .await?;
                if ch_s.send(recv_row).is_err() {
                    // If we can't send on the channel, the channel must've been dropped due to a
                    // panic in the worker thread. So we try to join the compute task to resume the
                    // panic
                    resume_unwind(jh.await.map(drop).expect_err("expected thread error"));
                };
            }
        }

        if S::MALICIOUS_SECURITY {
            let (mut kos_send, mut kos_recv) = sub_conn.byte_stream().await?;
            let success = 'success: {
                let Some(blk) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.as_stream().send(blk).await?;

                {
                    let mut kos_recv = kos_recv.as_stream();
                    let u = kos_recv.next().await.unwrap().unwrap();
                    kos_ch_s_task.send(u).unwrap();
                }

                true
            };
            if !success {
                resume_unwind(jh.await.map(drop).expect_err("expected thread error"));
            }
        }

        let (owned_ots, base_rngs, base_choices) = jh.await.expect("panic in worker thread")?;
        self.base_rngs = base_rngs;
        self.base_choices = base_choices;
        *ots = owned_ots;
        Ok(())
    }
}

impl SemiHonest for OtExtensionReceiver<SemiHonestMarker> {}
impl SemiHonest for OtExtensionReceiver<MaliciousMarker> {}

impl Malicious for OtExtensionReceiver<MaliciousMarker> {}

impl<S: Security> OtExtensionReceiver<S> {
    /// Create a new sender for the given [`Connection`].
    pub fn new(conn: Connection) -> Self {
        Self::new_with_rng(conn, StdRng::from_os_rng())
    }

    /// Create a new sender for the given [`Connection`] and [`StdRng`].
    ///
    /// For an rng seeded with a fixed seed, the output is deterministic.
    pub fn new_with_rng(mut conn: Connection, mut rng: StdRng) -> Self {
        let base_ot = SimplestOt::new_with_rng(conn.sub_connection(), StdRng::from_rng(&mut rng));
        Self {
            rng,
            base_ot,
            conn,
            base_rngs: vec![],
            batch_size: DEFAULT_OT_BATCH_SIZE,
            security: PhantomData,
        }
    }

    /// Set the OT batch size for the receiver.
    ///
    /// If the receiver batch size is changed, the senders's must also be
    /// changed (see [`OtExtensionSender::with_batch_size`]).
    /// Note that [`OtExtensionReceiver::receive`] methods will fail if `count %
    /// self.batch_size()` is not divisable by 128.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// The currently configured OT batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Returns true if base OTs have been performed. Subsequent calls to send
    /// will not perform base OTs again.
    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    /// Perform base OTs for later extension. Subsequent calls to send
    /// will not perform base OTs again.
    pub async fn do_base_ots(&mut self) -> Result<(), Error> {
        let base_ots = self.base_ot.send(BASE_OT_COUNT).await?;
        self.base_rngs = base_ots
            .into_iter()
            .map(|[s1, s2]| [AesRng::from_seed(s1), AesRng::from_seed(s2)])
            .collect();
        Ok(())
    }
}

impl<S: Security> Connected for OtExtensionReceiver<S> {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl<S: Security> RotReceiver for OtExtensionReceiver<S> {
    type Error = Error;

    /// Receiver part of OT extension.
    ///
    /// # Panics
    /// - If `choices.len()` is not divisable by 128.
    /// - If `choices.len() % self.batch_size()` is not divisable by 128.
    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::OT_EXTENSION))]
    async fn receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
        choices: &[Choice],
    ) -> Result<(), Self::Error> {
        assert_eq!(choices.len(), ots.len());
        assert_eq!(
            0,
            choices.len() % 128,
            "choices.len() must be multiple of 128"
        );
        let batch_size = self.batch_size();
        let count = choices.len();
        let batch_size_remainder = count % batch_size;
        assert_eq!(
            0,
            batch_size_remainder % 128,
            "count % batch_size must be multiple of 128"
        );

        if !self.has_base_ots() {
            self.do_base_ots().await?;
        }

        let mut sub_conn = self.conn.sub_connection();

        let cols_byte_batch = batch_size / 8;
        let choice_vec = choices_to_u8_vec(choices);

        let (ch_s, mut ch_r) = mpsc::unbounded_channel::<Vec<u8>>();
        let (kos_ch_s, mut kos_ch_r_task) = tokio::sync::mpsc::unbounded_channel::<Vec<Block>>();
        let (kos_ch_s_task, kos_ch_r) = std::sync::mpsc::channel::<Block>();
        let mut rng = StdRng::from_rng(&mut self.rng);

        let mut base_rngs = mem::take(&mut self.base_rngs);
        let owned_ots = mem::take(ots);
        let mut jh = spawn_compute(move || {
            let mut ots = owned_ots;
            let t_mat_size = if S::MALICIOUS_SECURITY {
                ots.len()
            } else {
                batch_size
            };
            let num_extra = (S::MALICIOUS_SECURITY as usize) * 128;
            let mut t_mat = vec![Block::ZERO; t_mat_size];
            let mut extra_t_mat = vec![Block::ZERO; num_extra];
            let mut extra_messages: Vec<Block> = Vec::zeroed(num_extra);
            let extra_choices = random_choices(num_extra, &mut rng);
            let extra_choice_vec = choices_to_u8_vec(&extra_choices);

            for (ots, choice_vec, extra) in [
                (&mut ots[..], &choice_vec, false),
                (&mut extra_messages[..], &extra_choice_vec, true),
            ] {
                for (chunk_idx, (output_chunk, choice_batch)) in ots
                    .chunks_mut(batch_size)
                    .zip(choice_vec.chunks(cols_byte_batch))
                    .enumerate()
                {
                    let curr_batch_size = output_chunk.len();
                    let chunk_t_mat = if S::MALICIOUS_SECURITY {
                        if extra {
                            &mut extra_t_mat
                        } else {
                            let offset = chunk_idx * batch_size;
                            &mut t_mat[offset..offset + curr_batch_size]
                        }
                    } else {
                        &mut t_mat[..curr_batch_size]
                    };
                    assert_eq!(output_chunk.len(), chunk_t_mat.len());
                    assert_eq!(choice_batch.len() * 8, chunk_t_mat.len());
                    let chunk_t_mat: &mut [u8] = bytemuck::must_cast_slice_mut(chunk_t_mat);
                    // might change for last chunk
                    let cols_byte_batch = choice_batch.len();
                    for (row, [rng1, rng2]) in chunk_t_mat
                        .chunks_exact_mut(cols_byte_batch)
                        .zip(&mut base_rngs)
                    {
                        rng1.fill_bytes(row);
                        let mut send_row = vec![0_u8; cols_byte_batch];
                        rng2.fill_bytes(&mut send_row);
                        // TODO wouldn't this be better on Blocks instead of u8?
                        for ((v2, v1), choices) in send_row.iter_mut().zip(row).zip(choice_batch) {
                            *v2 ^= *v1 ^ *choices;
                        }
                        ch_s.send(send_row)?;
                    }
                    let output_bytes = bytemuck::cast_slice_mut(output_chunk);
                    transpose_bitmatrix(
                        &chunk_t_mat[..BASE_OT_COUNT * cols_byte_batch],
                        output_bytes,
                        BASE_OT_COUNT,
                    );
                    if S::MALICIOUS_SECURITY {
                        FIXED_KEY_HASH.tccr_hash_slice_mut(output_chunk, |i| {
                            Block::from(chunk_idx * batch_size + i)
                        });
                    } else {
                        FIXED_KEY_HASH.cr_hash_slice_mut(output_chunk);
                    }
                }
            }

            if S::MALICIOUS_SECURITY {
                // dropping ch_s is important so the async task exits the ch_r loop
                drop(ch_s);
                let seed = kos_ch_r.recv()?;

                let mut t1 = extra_t_mat;
                let mut t2 = vec![Block::ZERO; BASE_OT_COUNT];

                let mut x1 = Block::from_choices(&extra_choices);
                let mut x2 = Block::ZERO;

                let rng = AesRng::from_seed(seed);

                let t_mat_ref = &t_mat;
                let batches = count / batch_size;
                let batch_sizes = iter::repeat(batch_size)
                    .take(batches)
                    .chain((batch_size_remainder != 0).then_some(batch_size_remainder));

                let choice_blocks: Vec<_> = choice_vec
                    .chunks_exact(Block::BYTES)
                    .map(|chunk| Block::try_from(chunk).expect("chunk is 16 bytes"))
                    .collect();

                let challenges: Vec<Block> = rng
                    .sample_iter(StandardUniform)
                    .take(choice_blocks.len())
                    .collect();

                for (x, s) in choice_blocks.iter().zip(challenges.iter()) {
                    let (xi, xi2) = x.clmul(s);
                    x1 ^= xi;
                    x2 ^= xi2;
                }

                let block_batch_size = batch_size / BASE_OT_COUNT;

                let challenge_iter =
                    batch_sizes
                        .clone()
                        .enumerate()
                        .flat_map(|(batch, curr_batch_size)| {
                            challenges[batch * block_batch_size
                                ..batch * block_batch_size + curr_batch_size / BASE_OT_COUNT]
                                .iter()
                                .cycle()
                                .take(curr_batch_size)
                        });
                let t_idx_iter = batch_sizes.flat_map(|curr_batch_size| {
                    (0..BASE_OT_COUNT).flat_map(move |t_idx| {
                        iter::repeat_n(t_idx, curr_batch_size / BASE_OT_COUNT)
                    })
                });

                for ((t, s), t_idx) in t_mat_ref.iter().zip(challenge_iter).zip(t_idx_iter) {
                    let (ti, ti2) = t.clmul(&s);
                    t1[t_idx] ^= ti;
                    t2[t_idx] ^= ti2;
                }

                for (t1i, t2i) in t1.iter_mut().zip(&mut t2) {
                    *t1i = Block::gf_reduce(t1i, t2i);
                }
                t1.push(Block::gf_reduce(&x1, &x2));
                kos_ch_s.send(t1).unwrap();
            }
            Ok::<_, Error>((ots, base_rngs))
        });

        let (mut send, _) = sub_conn.byte_stream().await?;
        while let Some(row) = ch_r.recv().await {
            send.write_all(&row).await.map_err(Error::Communication)?;
        }

        if S::MALICIOUS_SECURITY {
            // If the worker thread panics we break early from the above loop. We check for
            // the panic to prevent a deadlock where we try to get the next message but the
            // peer is still in the worker thread
            let err = poll_fn(|cx| match jh.poll_unpin(cx) {
                Poll::Ready(res) => Poll::Ready(res.map(drop)),
                Poll::Pending => Poll::Ready(Ok(())),
            })
            .await;
            if let Err(err) = err {
                resume_unwind(err);
            };
            let (mut kos_send, mut kos_recv) = sub_conn.byte_stream().await?;

            let seed = {
                let mut kos_recv = kos_recv.as_stream::<Block>();
                kos_recv.next().await.ok_or(Error::UnexcpectedClose)??
            };

            let success = 'success: {
                if kos_ch_s_task.send(seed).is_err() {
                    break 'success false;
                }

                let mut kos_send = kos_send.as_stream::<Vec<Block>>();
                let Some(v) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.send(v).await.map_err(Error::Communication)?;

                true
            };
            if !success {
                resume_unwind(jh.await.map(drop).expect_err("expected thread error"));
            }
        }

        let (owned_ots, base_rngs) = jh.await.expect("panic in worker thread")?;

        self.base_rngs = base_rngs;
        *ots = owned_ots;
        Ok(())
    }
}

impl<S: Security> CotSender for OtExtensionSender<S> {
    type Error = Error;

    async fn correlated_send_into<B, F>(
        &mut self,
        ots: &mut B,
        correlation: F,
    ) -> Result<(), Self::Error>
    where
        B: Buf<Block>,
        F: FnMut(usize) -> Block + Send,
    {
        CorrelatedFromRandom::new(self)
            .correlated_send_into(ots, correlation)
            .await
    }
}

impl<S: Security> CotReceiver for OtExtensionReceiver<S> {
    type Error = Error;

    async fn correlated_receive_into<B>(
        &mut self,
        ots: &mut B,
        choices: &[Choice],
    ) -> Result<(), Self::Error>
    where
        B: Buf<Block>,
    {
        CorrelatedFromRandom::new(self)
            .correlated_receive_into(ots, choices)
            .await
    }
}

fn choices_to_u8_vec(choices: &[Choice]) -> Vec<u8> {
    assert_eq!(0, choices.len() % 8);
    let mut v = vec![0_u8; choices.len() / 8];
    for (chunk, byte) in choices.chunks_exact(8).zip(&mut v) {
        for (i, choice) in chunk.iter().enumerate() {
            *byte ^= choice.unwrap_u8() << i;
        }
    }
    v
}

impl From<std::sync::mpsc::RecvError> for Error {
    fn from(_: std::sync::mpsc::RecvError) -> Self {
        Error::AsyncTaskDropped
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::AsyncTaskDropped
    }
}

#[cfg(test)]
mod tests {

    use cryprot_core::Block;
    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        CotReceiver, CotSender, MaliciousMarker, RotReceiver, RotSender,
        extension::{
            DEFAULT_OT_BATCH_SIZE, OtExtensionReceiver, OtExtensionSender,
            SemiHonestOtExtensionReceiver, SemiHonestOtExtensionSender,
        },
        random_choices,
    };

    #[tokio::test]
    async fn test_extension() {
        let _g = init_tracing();
        const COUNT: usize = 2 * DEFAULT_OT_BATCH_SIZE;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = SemiHonestOtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = SemiHonestOtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_extension_half_batch() {
        let _g = init_tracing();
        const COUNT: usize = 2 * DEFAULT_OT_BATCH_SIZE + DEFAULT_OT_BATCH_SIZE / 2;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = SemiHonestOtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = SemiHonestOtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_extension_partial_batch() {
        let _g = init_tracing();
        const COUNT: usize = DEFAULT_OT_BATCH_SIZE / 2 + 128;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = SemiHonestOtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = SemiHonestOtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_extension_malicious_half_batch() {
        let _g = init_tracing();
        const COUNT: usize = DEFAULT_OT_BATCH_SIZE / 2;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = OtExtensionSender::<MaliciousMarker>::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::<MaliciousMarker>::new_with_rng(c2, rng2);

        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_extension_malicious_partial_batch() {
        let _g = init_tracing();
        const COUNT: usize = DEFAULT_OT_BATCH_SIZE + DEFAULT_OT_BATCH_SIZE / 2 + 128;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = OtExtensionSender::<MaliciousMarker>::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::<MaliciousMarker>::new_with_rng(c2, rng2);

        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_extension_malicious_multiple_batch() {
        let _g = init_tracing();
        const COUNT: usize = DEFAULT_OT_BATCH_SIZE * 2;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = OtExtensionSender::<MaliciousMarker>::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::<MaliciousMarker>::new_with_rng(c2, rng2);

        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }

    #[tokio::test]
    async fn test_correlated_extension() {
        let _g = init_tracing();
        const COUNT: usize = 128;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = SemiHonestOtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = SemiHonestOtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) = tokio::try_join!(
            sender.correlated_send(COUNT, |_| Block::ONES),
            receiver.correlated_receive(&choices)
        )
        .unwrap();
        for (i, ((r, s), c)) in recv_ots.into_iter().zip(send_ots).zip(choices).enumerate() {
            if bool::from(c) {
                assert_eq!(r ^ Block::ONES, s, "Block {i}");
            } else {
                assert_eq!(r, s, "Block {i}")
            }
        }
    }
}
