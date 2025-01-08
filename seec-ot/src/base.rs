use std::io;

use bitvec::slice::BitSlice;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, RistrettoPoint, Scalar};
use futures::{SinkExt, StreamExt};
use rand::{rngs::StdRng, Rng, SeedableRng};
use seec_core::{
    random_oracle::{Hash, RandomOracle},
    Block,
};
use seec_net::{Connection, ConnectionError, Id};
use subtle::{Choice, ConditionallySelectable};

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
    async fn send(&mut self, count: usize) -> Result<Vec<[Block; 2]>, Self::Error> {
        let a = Scalar::random(&mut self.rng);
        let mut A = RISTRETTO_BASEPOINT_TABLE * &a;
        let seed: Block = self.rng.gen();
        // commit to the seed
        let seed_commitment = seed.ro_hash();
        let (mut send_m1, mut recv_m2) = self
            .conn
            .request_response_stream_with_id(Id::new(0))
            .await?;
        send_m1
            .send((A, seed_commitment.as_bytes().clone()))
            .await?;

        let B_points: Vec<RistrettoPoint> = recv_m2.next().await.ok_or(Error::ClosedStream)??;
        if B_points.len() != count {
            return Err(Error::InsufficientPoints {
                expected: count,
                actual: B_points.len(),
            });
        }
        // decommit seed
        let (mut send_m3, _) = self.conn.stream_with_id(Id::new(1)).await?;
        send_m3.send(seed).await?;

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
    async fn receive(&mut self, choices: &BitSlice) -> Result<Vec<Block>, Self::Error> {
        let (mut send_m2, mut recv_m1) = self
            .conn
            .request_response_stream_with_id(Id::new(0))
            .await?;
        let (A, commitment): (RistrettoPoint, [u8; 32]) =
            recv_m1.next().await.ok_or(Error::ClosedStream)??;

        let (b_points, B_points): (Vec<_>, Vec<_>) = choices
            .iter()
            .map(|choice| {
                let b = Scalar::random(&mut self.rng);
                let B_0 = RISTRETTO_BASEPOINT_TABLE * &b;
                let B_1 = B_0 + A;
                let B_choice =
                    RistrettoPoint::conditional_select(&B_0, &B_1, Choice::from(u8::from(*choice)));
                (b, B_choice)
            })
            .unzip();

        send_m2.send(B_points).await?;
        let (_, mut recv_3) = self.conn.stream_with_id(Id::new(1)).await?;

        let seed: Block = recv_3.next().await.ok_or(Error::ClosedStream)??;
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
    use std::time::Instant;

    use anyhow::Result;
    use bitvec::bitvec;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use seec_net::testing::local_conn;

    use super::SimplestOt;
    use crate::{RotReceiver, RotSender};

    #[tokio::test]
    async fn base_rot() -> Result<()> {
        let (c1, c2) = local_conn().await?;
        let mut rng1 = StdRng::seed_from_u64(42);
        let rng2 = StdRng::seed_from_u64(42 * 42);
        let count = 128;
        let mut choices = bitvec!(0; count);

        rng1.fill(choices.as_raw_mut_slice());

        let mut sender = SimplestOt::new_with_rng(c1, rng1);
        let mut receiver = SimplestOt::new_with_rng(c2, rng2);
        let now = Instant::now();
        let (s_ot, r_ot) = tokio::try_join!(sender.send(count), receiver.receive(&choices))?;
        dbg!(now.elapsed());

        for ((r, s), c) in r_ot.into_iter().zip(s_ot).zip(choices) {
            assert_eq!(r, s[c as usize])
        }
        Ok(())
    }
}
