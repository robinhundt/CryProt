use std::io;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, RistrettoPoint, Scalar};
use futures::{SinkExt, StreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use seec_core::{
    random_oracle::{Hash, RandomOracle},
    Block,
};
use seec_net::{Connection, ConnectionError};
use subtle::{Choice, ConditionallySelectable};
use tracing::Level;

use crate::{RotReceiver, RotSender};

pub struct SimplestOt {
    rng: StdRng,
    conn: Connection,
}

impl SimplestOt {
    pub fn new(connection: Connection) -> Self {
        Self::new_with_rng(connection, StdRng::from_entropy())
    }

    pub fn new_with_rng(connection: Connection, rng: StdRng) -> SimplestOt {
        Self {
            conn: connection,
            rng,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("quic connection error")]
    Connection(#[from] ConnectionError),
    #[error("io communicaiton error")]
    Io(#[from] io::Error),
    #[error("insufficient points received. expected: {expected}, actual: {actual}")]
    InsufficientPoints { expected: usize, actual: usize },
    #[error("expected message but stream is closed")]
    ClosedStream,
    #[error("seed commitment and seed hash not equal")]
    CommitmentHashesNotEqual,
}

impl RotSender for SimplestOt {
    type Error = Error;

    #[allow(non_snake_case)]
    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn send(&mut self, count: usize) -> Result<Vec<[Block; 2]>, Self::Error> {
        let a = Scalar::random(&mut self.rng);
        let mut A = RISTRETTO_BASEPOINT_TABLE * &a;
        let seed: Block = self.rng.gen();
        // commit to the seed
        let seed_commitment = seed.ro_hash();
        let (mut send, mut recv) = self.conn.byte_stream().await?;
        {
            let mut send_m1 = send.as_stream();
            send_m1.send((A, *seed_commitment.as_bytes())).await?;
        }

        let B_points: Vec<RistrettoPoint> = {
            let mut recv_m2 = recv.as_stream();
            recv_m2.next().await.ok_or(Error::ClosedStream)??
        };
        if B_points.len() != count {
            return Err(Error::InsufficientPoints {
                expected: count,
                actual: B_points.len(),
            });
        }
        // decommit seed
        {
            let mut send_m3 = send.as_stream();
            send_m3.send(seed).await?;
        }

        A *= a;
        let ots = B_points
            .into_iter()
            .enumerate()
            .map(|(i, mut B)| {
                B *= a;
                let k0 = ro_hash_point(&B, i, seed);
                B -= A;
                let k1 = ro_hash_point(&B, i, seed);
                [k0, k1]
            })
            .collect();
        Ok(ots)
    }
}

impl RotReceiver for SimplestOt {
    type Error = Error;

    #[allow(non_snake_case)]
    #[tracing::instrument(level = Level::DEBUG, skip_all)]
    async fn receive(&mut self, choices: &[Choice]) -> Result<Vec<Block>, Self::Error> {
        let (mut send, mut recv) = self.conn.byte_stream().await?;
        let (A, commitment): (RistrettoPoint, [u8; 32]) = {
            let mut recv_m1 = recv.as_stream();
            recv_m1.next().await.ok_or(Error::ClosedStream)??
        };

        let (b_points, B_points): (Vec<_>, Vec<_>) = choices
            .iter()
            .map(|choice| {
                let b = Scalar::random(&mut self.rng);
                let B_0 = RISTRETTO_BASEPOINT_TABLE * &b;
                let B_1 = B_0 + A;
                let B_choice = RistrettoPoint::conditional_select(&B_0, &B_1, *choice);
                (b, B_choice)
            })
            .unzip();
        {
            let mut send_m2 = send.as_stream();
            send_m2.send(B_points).await?;
        }

        let seed: Block = {
            let mut recv_3 = recv.as_stream();
            recv_3.next().await.ok_or(Error::ClosedStream)??
        };
        if Hash::from_bytes(commitment) != seed.ro_hash() {
            return Err(Error::CommitmentHashesNotEqual);
        }
        let ots = b_points
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                let B = A * b;
                ro_hash_point(&B, i, seed)
            })
            .collect();
        Ok(ots)
    }
}

fn ro_hash_point(point: &RistrettoPoint, tweak: usize, seed: Block) -> Block {
    let mut ro = RandomOracle::new();
    ro.update(point.compress().as_bytes());
    ro.update(&tweak.to_le_bytes());
    // TODO wouldn't it be possible to use the seed as the blake3 key?
    ro.update(seed.as_bytes());
    let mut out_reader = ro.finalize_xof();
    let mut ret = Block::ZERO;
    out_reader.fill(ret.as_mut_bytes());
    ret
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    
    use rand::{rngs::StdRng, SeedableRng};
    use seec_core::test_utils::init_tracing;
    use seec_net::testing::local_conn;

    use super::SimplestOt;
    use crate::{random_choices, RotReceiver, RotSender};

    #[tokio::test]
    async fn base_rot() -> Result<()> {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await?;
        let mut rng1 = StdRng::seed_from_u64(42);
        let rng2 = StdRng::seed_from_u64(42 * 42);
        let count = 128;
        let choices = random_choices(count, &mut rng1);

        let mut sender = SimplestOt::new_with_rng(c1, rng1);
        let mut receiver = SimplestOt::new_with_rng(c2, rng2);
        let (s_ot, r_ot) = tokio::try_join!(sender.send(count), receiver.receive(&choices))?;

        for ((r, s), c) in r_ot.into_iter().zip(s_ot).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize])
        }
        Ok(())
    }
}
