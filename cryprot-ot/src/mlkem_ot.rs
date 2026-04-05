//! Post-quantum base OT using ML-KEM.
//!
//! Implements the MR19 protocol (Masny-Rindal, ePrint 2019/706, Figure 8)
//! instantiated with ML-KEM as per Section D.3.
//! See `docs/mlkem-ot-protocol.md` for the full protocol description.

use std::{io, mem::size_of};

use cryprot_core::{Block, buf::Buf, rand_compat::RngCompat, random_oracle::RandomOracle};
use cryprot_net::{Connection, ConnectionError};
use futures::{SinkExt, StreamExt};
use hybrid_array::typenum::Unsigned;
use ml_kem::{
    Ciphertext as MlKemCiphertext, EncodedSizeUser, KemCore, ParameterSet, SharedKey,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey as MlKemEncapsulationKey},
};
// ML-KEM parameter set selection. If multiple features are enabled, the highest
// wins.
cfg_if::cfg_if! {
    if #[cfg(feature = "ml-kem-base-ot-1024")] {
        use ml_kem::{MlKem1024 as MlKem, MlKem1024Params as MlKemParams};
    } else if #[cfg(feature = "ml-kem-base-ot-768")] {
        use ml_kem::{MlKem768 as MlKem, MlKem768Params as MlKemParams};
    } else if #[cfg(feature = "ml-kem-base-ot-512")] {
        use ml_kem::{MlKem512 as MlKem, MlKem512Params as MlKemParams};
    }
}
use module_lattice::{Encode, Field, NttPolynomial};
use rand::{RngExt, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha3::{
    Digest, Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use subtle::{Choice, ConditionallySelectable};
use tracing::Level;

use crate::{Connected, RotReceiver, RotSender, SemiHonest, phase};

// Define the ML-KEM base field (q = 3329).
module_lattice::define_field!(MlKemField, u16, u32, u64, 3329);

// Module dimension derived from the chosen ML-KEM parameter set.
type K = <MlKemParams as ParameterSet>::K;

type NttVector = module_lattice::NttVector<MlKemField, K>;

type U12 = hybrid_array::typenum::U12;

const ENCAPSULATION_KEY_LEN: usize =
    <MlKemEncapsulationKey<MlKemParams> as EncodedSizeUser>::EncodedSize::USIZE;
const CIPHERTEXT_LEN: usize = <MlKem as KemCore>::CiphertextSize::USIZE;
const HASH_DOMAIN_SEPARATOR: &[u8] = b"MlKemOt";

// Number of coefficients per polynomial (FIPS 203, Section 2: n = 256).
const NUM_COEFFICIENTS: usize = 256;

type Seed = [u8; 32];

type Rho = [u8; 32];

// Serialized t_hat is the encapsulation key minus the rho suffix.
const T_HAT_BYTES_LEN: usize = ENCAPSULATION_KEY_LEN - size_of::<Rho>();

// Parsed encapsulation key: ek = (t_hat, rho).
struct EncapsulationKey {
    t_hat: NttVector,
    rho: Rho,
}

impl EncapsulationKey {
    fn from_bytes(bytes: &[u8; ENCAPSULATION_KEY_LEN]) -> Self {
        let enc = bytes[..T_HAT_BYTES_LEN]
            .try_into()
            .expect("t_hat length mismatch");
        let t_hat = <NttVector as Encode<U12>>::decode(enc);
        let rho = bytes[T_HAT_BYTES_LEN..]
            .try_into()
            .expect("rho length mismatch");
        Self { t_hat, rho }
    }

    fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_LEN] {
        let encoded = <NttVector as Encode<U12>>::encode(&self.t_hat);
        let mut out = [0u8; ENCAPSULATION_KEY_LEN];
        out[..T_HAT_BYTES_LEN].copy_from_slice(encoded.as_slice());
        out[T_HAT_BYTES_LEN..].copy_from_slice(&self.rho);
        out
    }
}

impl std::ops::Sub<&NttVector> for &EncapsulationKey {
    type Output = EncapsulationKey;

    fn sub(self, rhs: &NttVector) -> EncapsulationKey {
        EncapsulationKey {
            t_hat: &self.t_hat - rhs,
            rho: self.rho,
        }
    }
}

impl std::ops::Add<&NttVector> for &EncapsulationKey {
    type Output = EncapsulationKey;

    fn add(self, rhs: &NttVector) -> EncapsulationKey {
        EncapsulationKey {
            t_hat: &self.t_hat + rhs,
            rho: self.rho,
        }
    }
}

// XOF: SHAKE-128(seed || i || j), see FIPS 203 Section 4.1.
fn xof(seed: &Seed, i: u8, j: u8) -> impl XofReader {
    let mut h = Shake128::default();
    h.update(seed);
    h.update(&[i, j]);
    h.finalize_xof()
}

// FIPS 203 Algorithm 7: SampleNTT.
// Rejection sampling from a byte stream to produce a pseudorandom NTT
// polynomial.
//
// Adapted from the ml-kem crate's `sample_ntt`.
fn sample_ntt_poly(xof: &mut impl XofReader) -> NttPolynomial<MlKemField> {
    const Q: u16 = MlKemField::Q;
    // Read 32 triples (3 bytes each) at a time from the XOF.
    // BUF_LEN must be divisible by 3 so pos always lands exactly on BUF_LEN.
    const BUF_LEN: usize = 32 * 3;
    let mut poly = NttPolynomial::<MlKemField>::default();
    let mut buf = [0u8; BUF_LEN];
    xof.read(&mut buf);
    let mut pos = 0;
    let mut i = 0;

    while i < NUM_COEFFICIENTS {
        // Refill the buffer from the XOF stream when exhausted.
        if pos >= BUF_LEN {
            xof.read(&mut buf);
            pos = 0;
        }

        let d1 = u16::from(buf[pos]) | ((u16::from(buf[pos + 1]) & 0x0F) << 8);
        let d2 = (u16::from(buf[pos + 1]) >> 4) | (u16::from(buf[pos + 2]) << 4);
        pos += 3;

        if d1 < Q {
            poly.0[i] = module_lattice::Elem::new(d1);
            i += 1;
        }
        if i < NUM_COEFFICIENTS && d2 < Q {
            poly.0[i] = module_lattice::Elem::new(d2);
            i += 1;
        }
    }

    poly
}

// Produces a pseudorandom NttVector from a seed by calling sample_ntt_poly k
// times, each with a different XOF stream: xof(seed, 0, j).
fn sample_ntt_vector(seed: &Seed) -> NttVector {
    NttVector::new(
        (0..K::USIZE)
            .map(|j| {
                let mut reader = xof(seed, 0, j as u8);
                sample_ntt_poly(&mut reader)
            })
            .collect(),
    )
}

// Maps an encapsulation key to an NttVector via SHA3-256.
// Only the t_hat component is used; rho is ignored.
// Corresponds to libOTe's `pkHash`.
fn hash_ek(ek: &EncapsulationKey) -> NttVector {
    let encoded = <NttVector as Encode<U12>>::encode(&ek.t_hat);
    let seed: Seed = sha3::Sha3_256::digest(encoded.as_slice()).into();
    sample_ntt_vector(&seed)
}

// Generate a random encapsulation key using the given randomness and rho.
//
// The result is indistinguishable from a real encapsulation key, since a real
// one has `t_hat = A_hat * s + e` and that is computationally indistinguishable
// from a pseudorandom vector in `T_q^k`.
fn random_ek(rng: &mut StdRng, rho: Rho) -> EncapsulationKey {
    let seed: Seed = rng.random();
    EncapsulationKey {
        t_hat: sample_ntt_vector(&seed),
        rho,
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("quic connection error")]
    Connection(#[from] ConnectionError),
    #[error("io communication error")]
    Io(#[from] io::Error),
    #[error(
        "invalid count of keys/ciphertexts received. expected: {expected}, actual_0: {actual_0}, actual_1: {actual_1}"
    )]
    InvalidDataCount {
        expected: usize,
        actual_0: usize,
        actual_1: usize,
    },
    #[error("expected message but stream is closed")]
    ClosedStream,
    #[error("ML-KEM decapsulation failed")]
    Decapsulation,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct EncapsulationKeyBytes(#[serde(with = "serde_bytes")] [u8; ENCAPSULATION_KEY_LEN]);

impl From<&EncapsulationKey> for EncapsulationKeyBytes {
    fn from(ek: &EncapsulationKey) -> Self {
        Self(ek.to_bytes())
    }
}

impl ConditionallySelectable for EncapsulationKeyBytes {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[u8; ENCAPSULATION_KEY_LEN]>::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct CiphertextBytes(#[serde(with = "serde_bytes")] [u8; CIPHERTEXT_LEN]);

impl ConditionallySelectable for CiphertextBytes {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[u8; CIPHERTEXT_LEN]>::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

// Message from receiver to sender: two values (r_0, r_1) per OT.
#[derive(Serialize, Deserialize)]
struct EncapsulationKeysMessage {
    rs_0: Vec<EncapsulationKeyBytes>,
    rs_1: Vec<EncapsulationKeyBytes>,
}

// Message from sender to receiver: two ciphertexts per OT.
#[derive(Serialize, Deserialize)]
struct CiphertextsMessage {
    cts_0: Vec<CiphertextBytes>,
    cts_1: Vec<CiphertextBytes>,
}

pub struct MlKemOt {
    rng: StdRng,
    conn: Connection,
}

impl SemiHonest for MlKemOt {}

impl MlKemOt {
    pub fn new(connection: Connection) -> Self {
        Self::new_with_rng(connection, rand::make_rng())
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

        if receiver_msg.rs_0.len() != count || receiver_msg.rs_1.len() != count {
            return Err(Error::InvalidDataCount {
                expected: count,
                actual_0: receiver_msg.rs_0.len(),
                actual_1: receiver_msg.rs_1.len(),
            });
        }

        let mut cts_0 = Vec::with_capacity(count);
        let mut cts_1 = Vec::with_capacity(count);
        for (i, (r_0_bytes, r_1_bytes)) in receiver_msg
            .rs_0
            .iter()
            .zip(receiver_msg.rs_1.iter())
            .enumerate()
        {
            // Step 5: Receive (r_0, r_1) from the receiver (done above).
            let r_0 = EncapsulationKey::from_bytes(&r_0_bytes.0);
            let r_1 = EncapsulationKey::from_bytes(&r_1_bytes.0);

            // Step 6: Reconstruct encapsulation keys: ek_j = r_j + hash_ek(r_{1-j}).
            let ek_0 = &r_0 + &hash_ek(&r_1);
            let ek_1 = &r_1 + &hash_ek(&r_0);

            // Step 7: Encapsulate to both reconstructed keys.
            let (ct_0, ss_0) = encapsulate(&(&ek_0).into(), &mut self.rng);
            let (ct_1, ss_1) = encapsulate(&(&ek_1).into(), &mut self.rng);

            // Step 8: Derive OT output keys.
            let key_0 = derive_ot_key(&ss_0, i);
            let key_1 = derive_ot_key(&ss_1, i);

            cts_0.push(ct_0);
            cts_1.push(ct_1);
            ots[i] = [key_0, key_1];
        }

        let sender_msg = CiphertextsMessage { cts_0, cts_1 };
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
        let mut rs_0 = Vec::with_capacity(count);
        let mut rs_1 = Vec::with_capacity(count);

        for choice in choices.iter() {
            // Step 1: Generate real keypair.
            let (dk, ek) = MlKem::generate(&mut RngCompat(&mut self.rng));
            let ek_bytes: [u8; ENCAPSULATION_KEY_LEN] = ek
                .as_bytes()
                .as_slice()
                .try_into()
                .expect("incorrect encapsulation key size");
            let ek = EncapsulationKey::from_bytes(&ek_bytes);

            // Step 2: Sample random key for position 1-b.
            let r_1_b = random_ek(&mut self.rng, ek.rho);

            // Step 3: Compute real key: r_b = ek - hash_ek(r_{1-b}).
            let r_b = &ek - &hash_ek(&r_1_b);
            let r_b_bytes: EncapsulationKeyBytes = (&r_b).into();
            let r_1_b_bytes: EncapsulationKeyBytes = (&r_1_b).into();

            // Step 4: Select (r_0, r_1) based on choice bit (constant-time).
            // If b=0: r_0 = real, r_1 = random.
            // If b=1: r_0 = random, r_1 = real.
            let r_0 = EncapsulationKeyBytes::conditional_select(&r_b_bytes, &r_1_b_bytes, *choice);
            let r_1 = EncapsulationKeyBytes::conditional_select(&r_1_b_bytes, &r_b_bytes, *choice);

            decap_keys.push(dk);
            rs_0.push(r_0);
            rs_1.push(r_1);
        }

        let receiver_msg = EncapsulationKeysMessage { rs_0, rs_1 };
        {
            let mut send_stream = send.as_stream();
            send_stream.send(receiver_msg).await?;
        }

        let sender_msg: CiphertextsMessage = {
            let mut recv_stream = recv.as_stream();
            recv_stream.next().await.ok_or(Error::ClosedStream)??
        };

        if sender_msg.cts_0.len() != count || sender_msg.cts_1.len() != count {
            return Err(Error::InvalidDataCount {
                expected: count,
                actual_0: sender_msg.cts_0.len(),
                actual_1: sender_msg.cts_1.len(),
            });
        }

        // Step 10-11: Decapsulate the chosen ciphertext and derive OT key.
        for (i, ((dk, choice), (ct_0, ct_1))) in decap_keys
            .iter()
            .zip(choices.iter())
            .zip(sender_msg.cts_0.iter().zip(sender_msg.cts_1.iter()))
            .enumerate()
        {
            let ct_b_bytes = CiphertextBytes::conditional_select(ct_0, ct_1, *choice).0;
            let ct_b: MlKemCiphertext<MlKem> = ct_b_bytes
                .as_slice()
                .try_into()
                .expect("incorrect ciphertext size");
            let shared_secret = dk.decapsulate(&ct_b).map_err(|_| Error::Decapsulation)?;
            let key_b = derive_ot_key(&shared_secret, i);
            ots[i] = key_b;
        }

        Ok(())
    }
}

// Encapsulates to the given key, returning the ciphertext and the shared key.
// Note: ML-KEM encapsulation is infallible - the Result in the ml-kem crate is
// for API generality.
fn encapsulate(
    ek: &EncapsulationKeyBytes,
    rng: &mut StdRng,
) -> (CiphertextBytes, SharedKey<MlKem>) {
    let parsed_ek = MlKemEncapsulationKey::<MlKemParams>::from_bytes((&ek.0).into());
    let (ct, ss): (MlKemCiphertext<MlKem>, SharedKey<MlKem>) = parsed_ek
        .encapsulate(&mut RngCompat(rng))
        .expect("encapsulation failed");
    (
        CiphertextBytes(ct.as_slice().try_into().expect("incorrect ciphertext size")),
        ss,
    )
}

// Derive an OT key from the ML-KEM shared key using a random oracle XOF,
// returning a Block-sized (128-bit) output.
fn derive_ot_key(key: &SharedKey<MlKem>, tweak: usize) -> Block {
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

    #[tokio::test]
    async fn mlkem_base_rot_single_ot() -> Result<()> {
        let _g = init_tracing();
        let (con1, con2) = local_conn().await?;
        let rng1 = StdRng::seed_from_u64(42);
        let rng2 = StdRng::seed_from_u64(43);
        let choices = vec![subtle::Choice::from(1)];

        let mut sender = MlKemOt::new_with_rng(con1, rng1);
        let mut receiver = MlKemOt::new_with_rng(con2, rng2);
        let (s_ot, r_ot) = tokio::try_join!(sender.send(1), receiver.receive(&choices))?;

        assert_eq!(r_ot[0], s_ot[0][1]);
        Ok(())
    }
}
