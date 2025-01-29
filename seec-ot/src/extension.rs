use std::{io, iter, mem};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use seec_core::{
    aes_hash::FIXED_KEY_HASH, aes_rng::AesRng, alloc::allocate_zeroed_vec, buf::Buf, tokio_rayon::spawn_compute, transpose::transpose_bitmatrix, utils::{and_inplace_elem, xor_inplace}, Block
};
use seec_net::{Connection, ConnectionError};
use subtle::{Choice, ConditionallySelectable};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Level;

use crate::{
    base::{self, SimplestOt},
    phase, random_choices, RotReceiver, RotSender,
};

pub const BASE_OT_COUNT: usize = 128;

pub const DEFAULT_OT_BATCH_SIZE: usize = 2_usize.pow(16);

pub struct OtExtensionSender {
    rng: StdRng,
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<AesRng>,
    base_choices: Vec<Choice>,
    delta: Option<Block>,
    batch_size: usize,
}

pub struct OtExtensionReceiver {
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<[AesRng; 2]>,
    batch_size: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to compute base OTs")]
    BaseOT(#[from] base::Error),
    #[error("connection error to peer")]
    Connection(#[from] ConnectionError),
    #[error("receive error")]
    Receive(#[source] io::Error),
    #[error("compute worker thread is unreachable")]
    WorkerThreadUnreachable,
    #[error("send error")]
    Send(#[source] io::Error),
}

impl OtExtensionSender {
    pub fn new(conn: Connection) -> Self {
        Self::new_with_rng(conn, StdRng::from_entropy())
    }

    pub fn new_with_rng(mut conn: Connection, mut rng: StdRng) -> Self {
        let base_ot =
            SimplestOt::new_with_rng(conn.sub_connection(), StdRng::from_rng(&mut rng).unwrap());
        Self {
            rng,
            base_ot,
            conn,
            base_rngs: vec![],
            base_choices: vec![],
            delta: None,
            batch_size: DEFAULT_OT_BATCH_SIZE,
        }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    pub async fn do_base_ots(&mut self) -> Result<(), Error> {
        let base_choices = random_choices(BASE_OT_COUNT, &mut self.rng);
        let base_ots = self.base_ot.receive(&base_choices).await?;
        self.base_rngs = base_ots.into_iter().map(AesRng::from_seed).collect();
        self.delta = Some(Block::from_choices(&base_choices));
        self.base_choices = base_choices;
        Ok(())
    }
}

impl RotSender for OtExtensionSender {
    type Error = Error;

    /// Sender part of OT extension.
    ///
    /// # Panics
    /// - If `count` is not divisable by 128.
    /// - If `count % self.batch_size()` is not divisable by 128.
    #[tracing::instrument(level = Level::DEBUG, skip_all)]
    #[tracing::instrument(target = "seec_metrics", level = Level::TRACE, skip_all, fields(phase = phase::OT_EXTENSION))]
    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        let count = ots.len();
        assert_eq!(0, count % 128, "count must be multiple of 128");
        let batch_size = self.batch_size();
        let batches = count / batch_size;
        let batch_size_remainder = count % batch_size;
        assert_eq!(
            0,
            batch_size_remainder % 128,
            "count % batch_size must be multiple of 128"
        );

        let batch_sizes = iter::repeat(batch_size)
            .take(batches)
            .chain(iter::once(batch_size_remainder));

        if !self.has_base_ots() {
            self.do_base_ots().await?;
        }

        let delta = self.delta.expect("base OTs are done");
        let mut sub_conn = self.conn.sub_connection();

        // channel for communication between async task and compute thread
        let (ch_s, ch_r) = std::sync::mpsc::channel::<Vec<Block>>();
        // take these to move them into compute thread, will be returned via ret channel
        let mut base_rngs = mem::take(&mut self.base_rngs);
        let base_choices = mem::take(&mut self.base_choices);
        let batch_sizes_th = batch_sizes.clone();
        let owned_ots = mem::take(ots);

        // spawn compute thread for CPU intensive work. This way we increase throughput
        // and don't risk of blocking tokio worker threads
        let jh = spawn_compute(move || {
            let mut ots = owned_ots;
            let mut transposed = allocate_zeroed_vec::<Block>(batch_size);

            // to increase throughput, we divide the `count` many OTs into batches of size
            // self.batch_size(). Crucially, this allows us to do the transpose
            // and hash step while not having received the complete data from the
            // OtExtensionReceiver.
            for (ot_batch, batch_size) in ots.chunks_mut(batch_size).zip(batch_sizes_th) {
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
                    let Ok(mut recv_row) = ch_r.recv() else {
                        // ch_s was dropped before completion, stop thread
                        return None;
                    };
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

                FIXED_KEY_HASH.cr_hash_slice_mut(bytemuck::cast_slice_mut(ot_batch));
            }

            Some((ots, base_rngs, base_choices))
        });

        let (_, mut recv) = sub_conn.byte_stream().await?;

        for batch_size in batch_sizes {
            for _ in 0..BASE_OT_COUNT {
                let mut recv_row = allocate_zeroed_vec(batch_size / Block::BITS);
                recv.read_exact(bytemuck::cast_slice_mut(&mut recv_row))
                    .await
                    .map_err(Error::Receive)?;
                if ch_s.send(recv_row).is_err() {
                    // If we can't send on the channel, the channel must've been dropped due to a
                    // panic in the worker thread. So we try to join the comput task to resume the
                    // panic
                    let _ = jh.await;
                    unreachable!(
                        "send should fail because of panic which is propagated by jh.await"
                    )
                };
            }
        }

        let (owned_ots, base_rngs, base_choices) = jh
            .await
            .expect("compute task received all data so should return Some");
        self.base_rngs = base_rngs;
        self.base_choices = base_choices;
        *ots = owned_ots;
        Ok(())
    }
}

impl OtExtensionReceiver {
    pub fn new(conn: Connection) -> Self {
        Self::new_with_rng(conn, StdRng::from_entropy())
    }

    pub fn new_with_rng(mut conn: Connection, rng: StdRng) -> Self {
        let base_ot = SimplestOt::new_with_rng(conn.sub_connection(), rng);
        Self {
            base_ot,
            conn,
            base_rngs: vec![],
            batch_size: DEFAULT_OT_BATCH_SIZE,
        }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    pub async fn do_base_ots(&mut self) -> Result<(), Error> {
        let base_ots = self.base_ot.send(BASE_OT_COUNT).await?;
        self.base_rngs = base_ots
            .into_iter()
            .map(|[s1, s2]| [AesRng::from_seed(s1), AesRng::from_seed(s2)])
            .collect();
        Ok(())
    }
}

impl RotReceiver for OtExtensionReceiver {
    type Error = Error;

    /// Receiver part of OT extension.
    ///
    /// # Panics
    /// - If `choices.len()` is not divisable by 128.
    /// - If `choices.len() % self.batch_size()` is not divisable by 128.
    #[tracing::instrument(level = Level::DEBUG, skip_all)]
    #[tracing::instrument(target = "seec_metrics", level = Level::TRACE, skip_all, fields(phase = phase::OT_EXTENSION))]
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

        let cols_byte_batch = batch_size / 8;

        let choice_vec = choices_to_u8_vec(choices);
        let mut sub_conn = self.conn.sub_connection();

        let (ch_s, mut ch_r) = mpsc::unbounded_channel::<Vec<u8>>();

        let mut base_rngs = mem::take(&mut self.base_rngs);
        let mut owned_ots = mem::take(ots);
        let jh = spawn_compute(move || {
            let mut t_mat = vec![0; BASE_OT_COUNT * cols_byte_batch];

            for (output_chunk, choice_batch) in owned_ots
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
                    if ch_s.send(send_row).is_err() {
                        // async task including ch_r is dropped, so we stop the thread
                        return None;
                    }
                }
                let output_bytes = bytemuck::cast_slice_mut(output_chunk);
                transpose_bitmatrix(
                    &t_mat[..BASE_OT_COUNT * cols_byte_batch],
                    output_bytes,
                    BASE_OT_COUNT,
                );
                FIXED_KEY_HASH.cr_hash_slice_mut(output_chunk);
            }

            Some((owned_ots, base_rngs))
        });

        let (mut send, _) = sub_conn.byte_stream().await?;
        while let Some(row) = ch_r.recv().await {
            send.write_all(&row).await.map_err(Error::Send)?;
        }

        let (owned_ots, base_rngs) = jh
            .await
            .expect("ch_r received all data, so thread completed");

        self.base_rngs = base_rngs;
        *ots = owned_ots;
        Ok(())
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

#[cfg(test)]
mod tests {

    use rand::{rngs::StdRng, SeedableRng};
    use seec_net::testing::{init_tracing, local_conn};

    use crate::{
        extension::{OtExtensionReceiver, OtExtensionSender, DEFAULT_OT_BATCH_SIZE},
        random_choices, RotReceiver, RotSender,
    };

    #[tokio::test]
    async fn test_extension() {
        let _g = init_tracing();
        const COUNT: usize = 2 * DEFAULT_OT_BATCH_SIZE;
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = OtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::new_with_rng(c2, rng2);
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
        let mut sender = OtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::new_with_rng(c2, rng2);
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
        let mut sender = OtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize]);
        }
    }
}
