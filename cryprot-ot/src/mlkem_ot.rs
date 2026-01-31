//! Post-quantum base OT using ML-KEM.

use std::io;

use cryprot_core::{Block, buf::Buf, rand_compat::RngCompat, random_oracle::RandomOracle};
use cryprot_net::{Connection, ConnectionError};
use futures::{SinkExt, StreamExt};
// ML-KEM variant: change to MlKem512/MlKem512Params or MlKem768/MlKem768Params
// for different security levels.
use ml_kem::{
    Ciphertext as MlKemCiphertext, EncodedSizeUser, KemCore, MlKem1024 as MlKem,
    MlKem1024Params as MlKemParams, SharedKey,
    array::typenum::Unsigned,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey as MlKemEncapsulationKey},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable};
use tracing::Level;

use crate::{Connected, RotReceiver, RotSender, SemiHonest, phase};

const ENCAPSULATION_KEY_LEN: usize =
    <MlKemEncapsulationKey<MlKemParams> as EncodedSizeUser>::EncodedSize::USIZE;
const CIPHERTEXT_LEN: usize = <MlKem as KemCore>::CiphertextSize::USIZE;
const HASH_DOMAIN_SEPARATOR: &[u8] = b"MlKemOt";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("quic connection error")]
    Connection(#[from] ConnectionError),
    #[error("io communication error")]
    Io(#[from] io::Error),
    #[error(
        "invalid count of keys/ciphertexts received. expected: {expected}, actual0: {actual0}, actual1: {actual1}"
    )]
    InvalidDataCount {
        expected: usize,
        actual0: usize,
        actual1: usize,
    },
    #[error("expected message but stream is closed")]
    ClosedStream,
    #[error("ML-KEM decapsulation failed")]
    Decapsulation,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct EncapKeyBytes(#[serde(with = "serde_bytes")] [u8; ENCAPSULATION_KEY_LEN]);

impl ConditionallySelectable for EncapKeyBytes {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[u8; ENCAPSULATION_KEY_LEN]>::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct CtBytes(#[serde(with = "serde_bytes")] [u8; CIPHERTEXT_LEN]);

impl ConditionallySelectable for CtBytes {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[u8; CIPHERTEXT_LEN]>::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

// Message from receiver to sender: two encapsulation keys per OT.
// For choice bit c, ek{c} is a real key, ek{1-c} is random bytes.
#[derive(Serialize, Deserialize)]
struct EncapsulationKeysMessage {
    eks0: Vec<EncapKeyBytes>,
    eks1: Vec<EncapKeyBytes>,
}

// Message from sender to receiver: two ciphertexts per OT.
#[derive(Serialize, Deserialize)]
struct CiphertextsMessage {
    cts0: Vec<CtBytes>,
    cts1: Vec<CtBytes>,
}

pub struct MlKemOt {
    rng: StdRng,
    conn: Connection,
}

/// Note: MlKemOt is not `Malicious` secure in itself.
impl SemiHonest for MlKemOt {}

impl MlKemOt {
    pub fn new(connection: Connection) -> Self {
        Self::new_with_rng(connection, StdRng::from_os_rng())
    }

    pub fn new_with_rng(connection: Connection, rng: StdRng) -> MlKemOt {
        Self {
            conn: connection,
            rng,
        }
    }
}

impl Connected for MlKemOt {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl RotSender for MlKemOt {
    type Error = Error;

    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::BASE_OT))]
    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        let count = ots.len();
        let (mut send, mut recv) = self.conn.byte_stream().await?;

        let receiver_msg: EncapsulationKeysMessage = {
            let mut recv_stream = recv.as_stream();
            recv_stream.next().await.ok_or(Error::ClosedStream)??
        };

        if receiver_msg.eks0.len() != count || receiver_msg.eks1.len() != count {
            return Err(Error::InvalidDataCount {
                expected: count,
                actual0: receiver_msg.eks0.len(),
                actual1: receiver_msg.eks1.len(),
            });
        }

        let mut cts0 = Vec::with_capacity(count);
        let mut cts1 = Vec::with_capacity(count);
        for (i, (ek0, ek1)) in receiver_msg
            .eks0
            .iter()
            .zip(receiver_msg.eks1.iter())
            .enumerate()
        {
            let (ct0, key0) = encapsulate(ek0, &mut self.rng);
            let key0 = hash(&key0, i);

            let (ct1, key1) = encapsulate(ek1, &mut self.rng);
            let key1 = hash(&key1, i);

            cts0.push(ct0);
            cts1.push(ct1);
            ots[i] = [key0, key1];
        }

        let sender_msg = CiphertextsMessage { cts0, cts1 };
        {
            let mut send_stream = send.as_stream();
            send_stream.send(sender_msg).await?;
        }

        Ok(())
    }
}

impl RotReceiver for MlKemOt {
    type Error = Error;

    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(count = ots.len()))]
    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = phase::BASE_OT))]
    async fn receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
        choices: &[Choice],
    ) -> Result<(), Self::Error> {
        let count = ots.len();
        assert_eq!(choices.len(), count);

        let (mut send, mut recv) = self.conn.byte_stream().await?;

        let mut decap_keys: Vec<DecapsulationKey<MlKemParams>> = Vec::with_capacity(count);
        let mut eks0 = Vec::with_capacity(count);
        let mut eks1 = Vec::with_capacity(count);

        for choice in choices.iter() {
            // Generate real keypair.
            let (dk, ek) = MlKem::generate(&mut RngCompat(&mut self.rng));
            let real_ek = EncapKeyBytes(
                ek.as_bytes()
                    .as_slice()
                    .try_into()
                    .expect("incorrect encapsulation key size"),
            );
            let fake_ek = EncapKeyBytes(self.rng.random());

            let ek0 = EncapKeyBytes::conditional_select(&real_ek, &fake_ek, *choice);
            let ek1 = EncapKeyBytes::conditional_select(&fake_ek, &real_ek, *choice);

            decap_keys.push(dk);
            eks0.push(ek0);
            eks1.push(ek1);
        }

        let receiver_msg = EncapsulationKeysMessage { eks0, eks1 };
        {
            let mut send_stream = send.as_stream();
            send_stream.send(receiver_msg).await?;
        }

        let sender_msg: CiphertextsMessage = {
            let mut recv_stream = recv.as_stream();
            recv_stream.next().await.ok_or(Error::ClosedStream)??
        };

        if sender_msg.cts0.len() != count || sender_msg.cts1.len() != count {
            return Err(Error::InvalidDataCount {
                expected: count,
                actual0: sender_msg.cts0.len(),
                actual1: sender_msg.cts1.len(),
            });
        }

        // Decapsulate the chosen ciphertext for each OT.
        for (i, ((dk, choice), (ct0, ct1))) in decap_keys
            .iter()
            .zip(choices.iter())
            .zip(sender_msg.cts0.iter().zip(sender_msg.cts1.iter()))
            .enumerate()
        {
            let chosen_ct: MlKemCiphertext<MlKem> =
                CtBytes::conditional_select(ct0, ct1, *choice).0.into();
            let shared_key = dk
                .decapsulate(&chosen_ct)
                .map_err(|_| Error::Decapsulation)?;
            let shared_key = hash(&shared_key, i);
            ots[i] = shared_key;
        }

        Ok(())
    }
}

// Encapsulates to the given key, returning the ciphertext and the shared key.
fn encapsulate(ek: &EncapKeyBytes, rng: &mut StdRng) -> (CtBytes, SharedKey<MlKem>) {
    let parsed_ek = MlKemEncapsulationKey::<MlKemParams>::from_bytes((&ek.0).into());
    let (ct, k): (MlKemCiphertext<MlKem>, SharedKey<MlKem>) = parsed_ek
        .encapsulate(&mut RngCompat(rng))
        .expect("encapsulation should not fail");
    (
        CtBytes(ct.as_slice().try_into().expect("incorrect ciphertext size")),
        k,
    )
}

// Derive an OT key from the ML-KEM shared key using a random oracle XOF,
// extracting a Block-sized (128-bit) output.
fn hash(key: &SharedKey<MlKem>, tweak: usize) -> Block {
    let mut ro = RandomOracle::new();
    ro.update(HASH_DOMAIN_SEPARATOR);
    ro.update(key.as_slice());
    ro.update(&tweak.to_le_bytes());
    let mut out = ro.finalize_xof();
    let mut block = Block::ZERO;
    out.fill(block.as_mut_bytes());
    block
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{SeedableRng, rngs::StdRng};

    use super::MlKemOt;
    use crate::{RotReceiver, RotSender, random_choices};

    #[tokio::test]
    async fn mlkem_base_rot_random_choices() -> Result<()> {
        let _g = init_tracing();
        let (con1, con2) = local_conn().await?;
        let mut rng1 = StdRng::seed_from_u64(42);
        let rng2 = StdRng::seed_from_u64(42 * 42);
        let count = 128;
        let choices = random_choices(count, &mut rng1);

        let mut sender = MlKemOt::new_with_rng(con1, rng1);
        let mut receiver = MlKemOt::new_with_rng(con2, rng2);
        let (s_ot, r_ot) = tokio::try_join!(sender.send(count), receiver.receive(&choices))?;

        for ((r, s), c) in r_ot.into_iter().zip(s_ot).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize])
        }
        Ok(())
    }

    #[tokio::test]
    async fn mlkem_base_rot_zero_choices() -> Result<()> {
        let _g = init_tracing();
        let (con1, con2) = local_conn().await?;
        let rng1 = StdRng::seed_from_u64(123);
        let rng2 = StdRng::seed_from_u64(456);
        let count = 128;
        let choices: Vec<_> = (0..count).map(|_| subtle::Choice::from(0)).collect();

        let mut sender = MlKemOt::new_with_rng(con1, rng1);
        let mut receiver = MlKemOt::new_with_rng(con2, rng2);
        let (s_ot, r_ot) = tokio::try_join!(sender.send(count), receiver.receive(&choices))?;

        for ((r, s), c) in r_ot.into_iter().zip(s_ot).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize])
        }
        Ok(())
    }

    #[tokio::test]
    async fn mlkem_base_rot_one_choices() -> Result<()> {
        let _g = init_tracing();
        let (con1, con2) = local_conn().await?;
        let rng1 = StdRng::seed_from_u64(789);
        let rng2 = StdRng::seed_from_u64(101112);
        let count = 128;
        let choices: Vec<_> = (0..count).map(|_| subtle::Choice::from(1)).collect();

        let mut sender = MlKemOt::new_with_rng(con1, rng1);
        let mut receiver = MlKemOt::new_with_rng(con2, rng2);
        let (s_ot, r_ot) = tokio::try_join!(sender.send(count), receiver.receive(&choices))?;

        for ((r, s), c) in r_ot.into_iter().zip(s_ot).zip(choices) {
            assert_eq!(r, s[c.unwrap_u8() as usize])
        }
        Ok(())
    }
}
