use std::io;

use cryprot_core::{
    buf::Buf, rand_compat::RngCompat, random_oracle::{Hash, RandomOracle}, Block
};
use cryprot_net::{Connection, ConnectionError};
use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use futures::{SinkExt, StreamExt};
use rand::{Rng, SeedableRng, rngs::StdRng};
use subtle::{Choice, ConditionallySelectable};
use tracing::Level;

use crate::{Connected, Malicious, RotReceiver, RotSender, SemiHonest, phase};

pub struct SimplestOt {
    rng: StdRng,
    conn: Connection,
}

impl SimplestOt {
    pub fn new(connection: Connection) -> Self {
        Self::new_with_rng(connection, StdRng::from_os_rng())
    }

    pub fn new_with_rng(connection: Connection, rng: StdRng) -> SimplestOt {
        Self {
            conn: connection,
            rng,
        }
    }
}

impl Connected for SimplestOt {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
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

impl SemiHonest for SimplestOt {}

impl Malicious for SimplestOt {}

impl RotSender for SimplestOt {
    type Error = Error;

    #[allow(non_snake_case)]
    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::BASE_OT))]
    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        let count = ots.len();
        let a = Scalar::random(&mut RngCompat(&mut self.rng));
        let mut A = RISTRETTO_BASEPOINT_TABLE * &a;
        let seed: Block = self.rng.random();
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
        for (i, (mut B, ots)) in B_points.into_iter().zip(ots.iter_mut()).enumerate() {
            B *= a;
            let k0 = ro_hash_point(&B, i, seed);
            B -= A;
            let k1 = ro_hash_point(&B, i, seed);
            *ots = [k0, k1];
        }
        Ok(())
    }
}

impl RotReceiver for SimplestOt {
    type Error = Error;

    #[allow(non_snake_case)]
    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::BASE_OT))]
    async fn receive_into(
        &mut self,
        choices: &[Choice],
        ots: &mut impl Buf<Block>,
    ) -> Result<(), Self::Error> {
        assert_eq!(choices.len(), ots.len());
        let (mut send, mut recv) = self.conn.byte_stream().await?;
        let (A, commitment): (RistrettoPoint, [u8; 32]) = {
            let mut recv_m1 = recv.as_stream();
            recv_m1.next().await.ok_or(Error::ClosedStream)??
        };

        let (b_points, B_points): (Vec<_>, Vec<_>) = choices
            .iter()
            .map(|choice| {
                let b = Scalar::random(&mut RngCompat(&mut self.rng));
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
        for (i, (b, ot)) in b_points.into_iter().zip(ots.iter_mut()).enumerate() {
            let B = A * b;
            *ot = ro_hash_point(&B, i, seed);
        }
        Ok(())
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
    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{SeedableRng, rngs::StdRng};

    use super::SimplestOt;
    use crate::{RotReceiver, RotSender, random_choices};

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
