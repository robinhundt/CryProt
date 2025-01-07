use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, Scalar};
use rand::{rngs::StdRng, Rng};
use seec_core::Block;
use seec_net::Connection;

use crate::RotSender;

pub struct SimplestOt {
    rng: StdRng,
    conn: Connection,
}

impl RotSender for SimplestOt {
    type Error = ();

    fn send(
        &mut self,
        count: usize,
    ) -> impl std::future::Future<Output = Result<Vec<[Block; 2]>, Self::Error>> + Send {
        let a = Scalar::random(&mut self.rng);
        let mut A = RISTRETTO_BASEPOINT_TABLE * &a;
        let seed: Block = self.rng.gen();
        todo!()
    }
}
