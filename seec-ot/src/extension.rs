use std::{
    mem::{self, MaybeUninit},
    thread,
    time::Duration,
};

use futures::{SinkExt, StreamExt};
use rand::{rngs::StdRng, thread_rng, RngCore, SeedableRng};
use seec_core::{
    aes_hash::FIXED_KEY_HASH,
    aes_rng::AesRng,
    transpose::transpose_bitmatrix_into,
    utils::{allocate_zeroed_vec, xor_inplace, xor_inplace_elem},
    Block,
};
use seec_net::Connection;
use subtle::Choice;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time::sleep,
};
use tracing::debug;

use crate::{base::SimplestOt, random_choices, RotReceiver, RotSender};

pub const BASE_OT_COUNT: usize = 128;

const OT_BATCH_SIZE: usize = 2_usize.pow(16);

pub struct OtExtensionSender {
    rng: StdRng,
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<AesRng>,
    base_choices: Vec<Choice>,
    delta: Option<Block>,
}

pub struct OtExtensionReceiver {
    rng: StdRng,
    base_ot: SimplestOt,
    conn: Connection,
    base_rngs: Vec<[AesRng; 2]>,
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
        }
    }

    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    pub async fn do_base_ots(&mut self) -> Result<(), ()> {
        let base_choices = random_choices(BASE_OT_COUNT, &mut self.rng);
        let base_ots = self.base_ot.receive(&base_choices).await.unwrap();
        self.base_rngs = base_ots
            .into_iter()
            .map(|seed| AesRng::from_seed(seed))
            .collect();
        self.delta = Some(Block::from_choices(&base_choices));
        self.base_choices = base_choices;
        Ok(())
    }
}

impl RotSender for OtExtensionSender {
    type Error = ();

    async fn send(&mut self, count: usize) -> Result<Vec<[seec_core::Block; 2]>, Self::Error> {
        assert_eq!(0, count % 8, "count must be multiple of 8");
        assert_eq!(0, count % OT_BATCH_SIZE);
        if !self.has_base_ots() {
            self.do_base_ots().await.unwrap();
        }

        let delta = self.delta.expect("base OTs are done");

        // let batches = count / OT_BATCH_SIZE;
        // for batch in 0..batches {
        //     let count = OT_BATCH_SIZE;
        // }

        // div by 8 because size of byte
        let cols_byte = count / 8;
        let mut v_mat = vec![0_u8; BASE_OT_COUNT * cols_byte];

        let zero_row = vec![0_u8; cols_byte];
        let mut row_iter = v_mat.chunks_exact_mut(cols_byte);
        let mut sub_conn = self.conn.sub_connection();

        let mut recv_row = vec![0; cols_byte];

        // TODO pipeline implementation so that transpose and hash can be done 
        // for first batch of ots while waiting on receiver

        for i in 0..BASE_OT_COUNT {
            let v_row = row_iter.next().unwrap();
            self.base_rngs[i].fill_bytes(v_row);
            let r = self.base_choices[i];
            // let recv_row = ch_r.recv().await.unwrap();
            let (_, mut recv) = sub_conn.byte_stream().await.unwrap();
            recv.read_exact(&mut recv_row).await.unwrap();
            // The following is a best-effort constant time implementation
            let xor_row = if r.unwrap_u8() == 0 {
                &zero_row
            } else {
                &recv_row
            };
            xor_inplace(v_row, &xor_row);
        }
        let mut v_mat_blocks = allocate_zeroed_vec(v_mat.len() / mem::size_of::<Block>());
        transpose_bitmatrix_into(
            &v_mat,
            bytemuck::cast_slice_mut(&mut v_mat_blocks),
            BASE_OT_COUNT,
        );

        let mut ots = allocate_zeroed_vec(count);
        // chunk into 5 len chunks so we can make use of AES-NI ILP
        const CHUNK_SIZE: usize = 9;
        let mut chunk_iter = v_mat_blocks.chunks_exact(CHUNK_SIZE);
        let mut ots_chunk_iter = ots.chunks_exact_mut(CHUNK_SIZE);
        for (chunk, out_ots_chunk) in chunk_iter.by_ref().zip(ots_chunk_iter.by_ref()) {
            macro_rules! load_arr {
                ($($idx:expr),+) => {
                    [
                        $(
                            chunk[$idx],
                            chunk[$idx] ^ delta,
                        )*
                    ]
                };
            }
            let arr = load_arr!(0, 1, 2, 3, 4, 5, 6, 7, 8);

            FIXED_KEY_HASH.cr_hash_blocks_b2b(&arr, bytemuck::cast_slice_mut(out_ots_chunk));
        }

        for (block, out_ot) in chunk_iter
            .remainder()
            .iter()
            .zip(ots_chunk_iter.into_remainder())
        {
            let x_0 = FIXED_KEY_HASH.cr_hash_block(*block);
            let x_1 = FIXED_KEY_HASH.cr_hash_block(*block ^ delta);
            *out_ot = [x_0, x_1]
        }

        Ok(ots)
    }
}

impl OtExtensionReceiver {
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
        }
    }

    pub fn has_base_ots(&self) -> bool {
        self.base_rngs.len() == BASE_OT_COUNT
    }

    pub async fn do_base_ots(&mut self) -> Result<(), ()> {
        let base_ots = self.base_ot.send(BASE_OT_COUNT).await.unwrap();
        self.base_rngs = base_ots
            .into_iter()
            .map(|[s1, s2]| [AesRng::from_seed(s1), AesRng::from_seed(s2)])
            .collect();
        Ok(())
    }
}

impl RotReceiver for OtExtensionReceiver {
    type Error = ();

    async fn receive(&mut self, choices: &[Choice]) -> Result<Vec<Block>, Self::Error> {
        assert_eq!(0, choices.len() % 8, "choices.len() must be multiple of 8");

        if !self.has_base_ots() {
            self.do_base_ots().await.unwrap();
        }

        let cols_byte = choices.len() / 8;
        // let mut t_mat = vec![0_u8; BASE_OT_COUNT * cols_byte];
        let mut t_mat = vec![0; BASE_OT_COUNT * cols_byte];
        let choice_vec = choices_to_u8_vec(choices);
        let mut i = 0;
        let (ch_s, mut ch_r) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut sub_conn = self.conn.sub_connection();
        tokio::spawn(async move {
            while let Some(row) = ch_r.recv().await {
                let (mut send, _) = sub_conn.byte_stream().await.unwrap();
                send.write_all(&row).await.unwrap();
                send.close().await.unwrap();
                debug!("sent row {i}");
            }
        });

        
        for (row, [rng1, rng2]) in t_mat.chunks_exact_mut(cols_byte).zip(&mut self.base_rngs) {
            i += 1;
            let mut send_row = vec![0_u8; cols_byte];
            rng1.fill_bytes(row);
            rng2.fill_bytes(&mut send_row);
            for ((v2, v1), choices) in send_row.iter_mut().zip(row).zip(&choice_vec) {
                *v2 ^= *v1 ^ *choices;
            }
            ch_s.send(send_row).unwrap();
        }
        let mut output = allocate_zeroed_vec(t_mat.len() / mem::size_of::<Block>());
        let output_bytes = bytemuck::cast_slice_mut(&mut output);
        transpose_bitmatrix_into(&t_mat, output_bytes, BASE_OT_COUNT);
        FIXED_KEY_HASH.cr_hash_slice_mut(&mut output);
        Ok(output)
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
    use std::time::Instant;

    use rand::{rngs::StdRng, SeedableRng};
    use seec_core::test_utils::init_tracing;
    use seec_net::testing::local_conn;

    use crate::{
        extension::{OtExtensionReceiver, OtExtensionSender},
        random_choices, RotReceiver, RotSender,
    };

    #[tokio::test]
    async fn test_extension() {
        let _g = init_tracing();
        const COUNT: usize = 2_usize.pow(24);
        let (c1, c2) = local_conn().await.unwrap();
        let rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(24);
        let choices = random_choices(COUNT, &mut rng2);
        let mut sender = OtExtensionSender::new_with_rng(c1, rng1);
        let mut receiver = OtExtensionReceiver::new_with_rng(c2, rng2);
        let (send_ots, recv_ots) =
            tokio::try_join!(sender.send(COUNT), receiver.receive(&choices)).unwrap();
        for ((r, s), c) in recv_ots.into_iter().zip(send_ots).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize])
        }
    }
}
