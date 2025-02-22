//! Fast OT extension using optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)] (semi-honest)
//! or [[KOS15]](https://eprint.iacr.org/2015/546.pdf) (malicious) protocol.
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
    random_oracle::{self},
    tokio_rayon::spawn_compute,
    transpose::transpose_bitmatrix,
    utils::{and_inplace_elem, xor_inplace},
};
use cryprot_net::{Connection, ConnectionError};
use futures::{FutureExt, SinkExt, StreamExt, future::poll_fn};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use subtle::{Choice, ConditionallySelectable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Level;

use crate::{
    Connected, Malicious, MaliciousMarker, RotReceiver, RotSender, Security, SemiHonest,
    SemiHonestMarker,
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

        let their_seed_comm: Option<random_oracle::Hash> = if S::MALICIOUS_SECURITY {
            let (_, mut rx) = sub_conn.stream().await?;
            Some(rx.next().await.ok_or(Error::UnexcpectedClose)??)
        } else {
            None
        };

        // channel for communication between async task and compute thread
        let (ch_s, ch_r) = std::sync::mpsc::channel::<Vec<Block>>();
        let (kos_ch_s, mut kos_ch_r_task) = tokio::sync::mpsc::unbounded_channel::<Block>();
        let (kos_ch_s_task, kos_ch_r) = std::sync::mpsc::channel::<Block>();
        // take these to move them into compute thread, will be returned via ret channel
        let mut base_rngs = mem::take(&mut self.base_rngs);
        let base_choices = mem::take(&mut self.base_choices);
        let mut batch_sizes_th = batch_sizes.clone();
        let owned_ots = mem::take(ots);
        let mut rng = StdRng::from_rng(&mut self.rng);

        // spawn compute thread for CPU intensive work. This way we increase throughput
        // and don't risk of blocking tokio worker threads
        let jh = spawn_compute(move || {
            let mut ots = owned_ots;
            let mut extra_messages: Vec<[Block; 2]> = Vec::zeroed(num_extra);
            let mut transposed = allocate_zeroed_vec::<Block>(batch_size);

            for (ots, batch_sizes) in [
                (
                    &mut ots[..],
                    &mut batch_sizes_th as &mut dyn Iterator<Item = _>,
                ),
                (&mut extra_messages[..], &mut iter::once(num_extra)),
            ] {
                // to increase throughput, we divide the `count` many OTs into batches of size
                // self.batch_size(). Crucially, this allows us to do the transpose
                // and hash step while not having received the complete data from the
                // OtExtensionReceiver.
                for (ot_batch, batch_size) in ots.chunks_mut(batch_size).zip(batch_sizes) {
                    let cols_byte_batch = batch_size / 8;
                    // we temporarily use the output OT buffer to hold the current chunk of the V
                    // matrix which we XOR with our received row or 0 and then
                    // transpose into `transposed`
                    let v_mat = bytemuck::cast_slice_mut(&mut ot_batch[..batch_size / 2]);
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

                    if !S::MALICIOUS_SECURITY {
                        FIXED_KEY_HASH.cr_hash_slice_mut(bytemuck::cast_slice_mut(ot_batch));
                    }
                }
            }

            if S::MALICIOUS_SECURITY {
                let my_seed: Block = rng.random();
                kos_ch_s.send(my_seed)?;
                let their_seed = kos_ch_r.recv()?;
                if commit(their_seed) != their_seed_comm.expect("set at after base ots") {
                    return Err(Error::WrongCommitment);
                }

                let seed = my_seed ^ their_seed;
                let mut rng = AesRng::from_seed(seed);

                let mut q1 = Block::ZERO;
                let mut q2 = Block::ZERO;
                for [msg, _] in ots.iter_mut().chain(extra_messages.iter_mut()) {
                    let challenge: Block = rng.random();
                    let (qi1, qi2) = msg.clmul(&challenge);
                    q1 ^= qi1;
                    q2 ^= qi2;
                }

                FIXED_KEY_HASH
                    .tccr_hash_slice_mut(cast_slice_mut(&mut ots), |idx| Block::from(idx / 2));

                let q = Block::gf_reduce(&q1, &q2);
                let received_x = kos_ch_r.recv()?;
                let received_t = kos_ch_r.recv()?;
                let tt = received_x.gf_mul(&delta) ^ q;
                if tt != received_t {
                    return Err(Error::MaliciousCheck);
                }
            }

            Ok((ots, base_rngs, base_choices))
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
            let (mut kos_send, mut kos_recv) = sub_conn.stream::<Block>().await?;
            let success = 'success: {
                let Some(blk) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.send(blk).await?;

                let blk = kos_recv.next().await.ok_or(Error::UnexcpectedClose)??;
                if kos_ch_s_task.send(blk).is_err() {
                    break 'success false;
                }
                let blk = kos_recv.next().await.ok_or(Error::UnexcpectedClose)??;
                if kos_ch_s_task.send(blk).is_err() {
                    break 'success false;
                }
                let blk = kos_recv.next().await.ok_or(Error::UnexcpectedClose)??;
                if kos_ch_s_task.send(blk).is_err() {
                    break 'success false;
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
        choices: &[Choice],
        ots: &mut impl Buf<Block>,
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

        let my_seed = if S::MALICIOUS_SECURITY {
            let (mut tx, _) = sub_conn.stream().await?;
            let seed = self.rng.random();
            tx.send(commit(seed)).await?;
            Some(seed)
        } else {
            None
        };

        let cols_byte_batch = batch_size / 8;
        let choice_vec = choices_to_u8_vec(choices);

        let (ch_s, mut ch_r) = mpsc::unbounded_channel::<Vec<u8>>();
        let (kos_ch_s, mut kos_ch_r_task) = tokio::sync::mpsc::unbounded_channel::<Block>();
        let (kos_ch_s_task, kos_ch_r) = std::sync::mpsc::channel::<Block>();
        let mut rng = StdRng::from_rng(&mut self.rng);

        let mut base_rngs = mem::take(&mut self.base_rngs);
        let owned_ots = mem::take(ots);
        let choices = (S::MALICIOUS_SECURITY).then(|| choices.to_owned());
        let mut jh = spawn_compute(move || {
            let mut ots = owned_ots;
            let mut t_mat = vec![0; BASE_OT_COUNT * cols_byte_batch];
            let num_extra = (S::MALICIOUS_SECURITY as usize) * 128;
            let mut extra_messages: Vec<Block> = Vec::zeroed(num_extra);
            let extra_choices = random_choices(num_extra, &mut rng);
            let extra_choice_vec = choices_to_u8_vec(&extra_choices);

            for (ots, choice_vec) in [
                (&mut ots[..], &choice_vec),
                (&mut extra_messages[..], &extra_choice_vec),
            ] {
                for (output_chunk, choice_batch) in ots
                    .chunks_mut(batch_size)
                    .zip(choice_vec.chunks(cols_byte_batch))
                {
                    // might change for last chunk
                    let cols_byte_batch = choice_batch.len();
                    for (row, [rng1, rng2]) in
                        t_mat.chunks_exact_mut(cols_byte_batch).zip(&mut base_rngs)
                    {
                        rng1.fill_bytes(row);
                        let mut send_row = vec![0_u8; cols_byte_batch];
                        rng2.fill_bytes(&mut send_row);
                        for ((v2, v1), choices) in send_row.iter_mut().zip(row).zip(choice_batch) {
                            *v2 ^= *v1 ^ *choices;
                        }
                        ch_s.send(send_row)?;
                    }
                    let output_bytes = bytemuck::cast_slice_mut(output_chunk);
                    transpose_bitmatrix(
                        &t_mat[..BASE_OT_COUNT * cols_byte_batch],
                        output_bytes,
                        BASE_OT_COUNT,
                    );
                    if !S::MALICIOUS_SECURITY {
                        FIXED_KEY_HASH.cr_hash_slice_mut(output_chunk);
                    }
                }
            }

            if S::MALICIOUS_SECURITY {
                // dropping ch_s is important so the async task exits the ch_r loop
                drop(ch_s);
                let my_seed = my_seed.expect("initialized earlier");
                let their_seed = kos_ch_r.recv()?;
                kos_ch_s.send(my_seed)?;

                let seed = my_seed ^ their_seed;
                let mut rng = AesRng::from_seed(seed);

                let mut x = Block::ZERO;
                let mut t1 = Block::ZERO;
                let mut t2 = Block::ZERO;
                let zero_one = [Block::ZERO, Block::ONES];
                for (msg, choice) in ots
                    .iter_mut()
                    .zip(&choices.expect("set befor spawn_compute if malicious"))
                    .chain(extra_messages.iter_mut().zip(&extra_choices))
                {
                    let challenge: Block = rng.random();
                    x ^= challenge & zero_one[choice.unwrap_u8() as usize];
                    let (ti1, ti2) = msg.clmul(&challenge);
                    t1 ^= ti1;
                    t2 ^= ti2;
                }
                FIXED_KEY_HASH.tccr_hash_slice_mut(&mut ots, Block::from);

                t1 = Block::gf_reduce(&t1, &t2);

                kos_ch_s.send(x)?;
                kos_ch_s.send(t1)?;
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
            let (mut kos_send, mut kos_recv) = sub_conn.stream::<Block>().await?;

            let blk = kos_recv.next().await.ok_or(Error::UnexcpectedClose)??;

            let success = 'success: {
                if kos_ch_s_task.send(blk).is_err() {
                    break 'success false;
                }
                let Some(blk) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.send(blk).await?;
                let Some(blk) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.send(blk).await?;
                let Some(blk) = kos_ch_r_task.recv().await else {
                    break 'success false;
                };
                kos_send.send(blk).await?;

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

fn commit(b: Block) -> random_oracle::Hash {
    random_oracle::hash(b.as_bytes())
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

    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        MaliciousMarker, RotReceiver, RotSender,
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
    async fn test_extension_malicious() {
        let _g = init_tracing();
        const COUNT: usize = DEFAULT_OT_BATCH_SIZE;
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
}
