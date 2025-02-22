//! Noisy-Vole computes for chosen c and delta, a and b s.t. a = b + c * delta
//! in GF(2^128).

use std::io;

use bitvec::{order::Lsb0, vec::BitVec};
use bytemuck::{cast_slice, cast_slice_mut};
use cryprot_core::{Block, aes_rng::AesRng, buf::Buf, tokio_rayon::spawn_compute};
use cryprot_net::{Connection, ConnectionError};
use rand::{Rng, SeedableRng};
use subtle::{Choice, ConditionallySelectable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Level;

use crate::phase;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to establish sub connection")]
    Connection(#[from] ConnectionError),
    #[error("error in sending/receiving noisy vole data")]
    Io(#[from] io::Error),
}

pub struct NoisyVoleSender {
    conn: Connection,
}

impl NoisyVoleSender {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// For chosen delta compute b s.t. a = b + c * delta.
    ///
    /// Operations are performed in GF(2^128). Note that the bits of `delta`
    /// must be equal to the choice bits for the passed base OTs.
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::NOISY_VOLE))]
    pub async fn send(
        &mut self,
        size: usize,
        delta: Block,
        ots: Vec<Block>,
    ) -> Result<Vec<Block>, Error> {
        assert_eq!(Block::BITS, ots.len());
        let mut msg: Vec<Block> = Vec::zeroed(Block::BITS * size);
        let (_, mut rx) = self.conn.byte_stream().await?;
        rx.read_exact(cast_slice_mut(&mut msg)).await?;

        let jh = spawn_compute(move || {
            let mut b = vec![Block::ZERO; size];
            let delta_arr = <[u64; 2]>::from(delta);
            let xb: BitVec<u64, Lsb0> = BitVec::from_slice(&delta_arr);
            let mut k = 0;
            for (i, ot) in ots.iter().enumerate() {
                let mut rng = AesRng::from_seed(*ot);

                for bj in &mut b {
                    let mut tmp: Block = rng.random();

                    tmp ^=
                        Block::conditional_select(&Block::ZERO, &msg[k], Choice::from(xb[i] as u8));
                    *bj ^= tmp;
                    k += 1;
                }
            }
            b
        });

        Ok(jh.await.expect("worker panic"))
    }
}

pub struct NoisyVoleReceiver {
    conn: Connection,
}

impl NoisyVoleReceiver {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// For chosen c compute a s.t. a = b + c * delta.
    ///
    /// Operations are performed in GF(2^128). Note that the bits of `delta` for
    /// the [`NoisyVoleSender`] must be equal to the choice bits for the
    /// passed base OTs.
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::NOISY_VOLE))]
    pub async fn receive(
        &mut self,
        c: Vec<Block>,
        ots: Vec<[Block; 2]>,
    ) -> Result<Vec<Block>, Error> {
        let jh = spawn_compute(move || {
            let mut a = Vec::zeroed(c.len());
            let mut msg: Vec<Block> = Vec::zeroed(ots.len() * a.len());

            let mut k = 0;
            for (i, [ot0, ot1]) in ots.into_iter().enumerate() {
                let mut rng = AesRng::from_seed(ot0);
                let t1 = Block::ONE << i;

                for (aj, cj) in a.iter_mut().zip(c.iter()) {
                    msg[k] = rng.random();
                    *aj ^= msg[k];
                    let t0 = t1.gf_mul(cj);
                    msg[k] ^= t0;
                    k += 1;
                }

                let mut rng = AesRng::from_seed(ot1);
                for m in &mut msg[k - c.len()..k] {
                    let t: Block = rng.random();
                    *m ^= t;
                }
            }
            (msg, a)
        });
        let (mut tx, _) = self.conn.byte_stream().await?;
        let (msg, a) = jh.await.expect("worker panic");
        tx.write_all(cast_slice(&msg)).await?;
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::{order::Lsb0, slice::BitSlice};
    use cryprot_core::{Block, utils::xor_inplace};
    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use crate::noisy_vole::{NoisyVoleReceiver, NoisyVoleSender};

    #[tokio::test]
    async fn test_noisy_vole() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();
        let mut sender = NoisyVoleSender::new(c1);
        let mut receiver = NoisyVoleReceiver::new(c2);
        let mut rng = StdRng::seed_from_u64(423423);
        let r_ots: Vec<[Block; 2]> = (0..128).map(|_| rng.random()).collect();
        let delta: Block = rng.random();
        let choice = BitSlice::<_, Lsb0>::from_slice(delta.as_bytes());
        let s_ots: Vec<_> = r_ots
            .iter()
            .zip(choice)
            .map(|(ots, c)| ots[*c as usize].clone())
            .collect();

        let size = 200;
        let mut c: Vec<_> = (0..size).map(|_| rng.random()).collect();

        let (mut b, a) = tokio::try_join!(
            sender.send(size, delta, s_ots),
            receiver.receive(c.clone(), r_ots)
        )
        .unwrap();

        for ci in &mut c {
            *ci = ci.gf_mul(&delta);
        }

        xor_inplace(&mut b, &c);

        assert_eq!(a, b);
    }
}
