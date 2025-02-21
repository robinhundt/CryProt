#![allow(non_snake_case)]
use std::{io, marker::PhantomData, mem};

use bytemuck::cast_slice_mut;
use cryprot_codes::ex_conv::{ExConvCode, ExConvCodeConfig};
use cryprot_core::{
    AES_PAR_BLOCKS, Block, aes_hash::FIXED_KEY_HASH, alloc::HugePageMemory, buf::Buf,
    random_oracle::Hash, tokio_rayon::spawn_compute,
};
use cryprot_net::{Connection, ConnectionError};
use cryprot_pprf::{PprfConfig, RegularPprfReceiver, RegularPprfSender};
use futures::{SinkExt, StreamExt};
use rand::{Rng, SeedableRng, rngs::StdRng};
use subtle::Choice;
use tracing::Level;

use crate::{
    Connected, Malicious, MaliciousMarker, RandChoiceRotReceiver, RandChoiceRotSender, RotReceiver,
    RotSender, Security, SemiHonest, SemiHonestMarker,
    extension::{self, OtExtensionReceiver, OtExtensionSender},
    noisy_vole::{self, NoisyVoleReceiver, NoisyVoleSender},
};

pub const SECURITY_PARAMETER: usize = 128;
const SCALER: usize = 2;

pub type SemiHonestSilentOtSender = SilentOtSender<SemiHonestMarker>;
pub type SemiHonestSilentOtReceiver = SilentOtReceiver<SemiHonestMarker>;

pub type MaliciousSilentOtSender = SilentOtSender<MaliciousMarker>;
pub type MaliciousSilentOtReceiver = SilentOtReceiver<MaliciousMarker>;

pub struct SilentOtSender<S> {
    conn: Connection,
    ot_sender: OtExtensionSender<SemiHonestMarker>,
    rng: StdRng,
    s: PhantomData<S>,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MultType {
    #[default]
    ExConv7x24,
    ExConv21x24,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to perform base OTs for silent OTs")]
    BaseOt(#[from] extension::Error),
    #[error("error in pprf expansion for silent OTs")]
    Pprf(#[from] cryprot_pprf::Error),
    #[error("io error during malicious check")]
    Io(#[from] io::Error),
    #[error("error in connection to peer")]
    Connection(#[from] ConnectionError),
    #[error("error in noisy vole during malicious check")]
    NoisyVole(#[from] noisy_vole::Error),
    #[error("sender did not transmit hash in malicious check")]
    MissingSenderHash,
    #[error("receiver did not transmit seed in malicious check")]
    MissingReceiverSeed,
    #[error("malicious check failed")]
    MaliciousCheck,
}

impl<S: Security> SilentOtSender<S> {
    pub fn new(mut conn: Connection) -> Self {
        let ot_sender = OtExtensionSender::new(conn.sub_connection());
        Self {
            conn,
            ot_sender,
            rng: StdRng::from_os_rng(),
            s: PhantomData,
        }
    }

    // Needed minimum buffer size when using `correlated_send_into` method.
    pub fn ots_buf_size(count: usize) -> usize {
        let conf = Config::configure(count, MultType::default());
        let pprf_conf = PprfConfig::from(conf);
        pprf_conf.size()
    }

    pub async fn random_send(&mut self, count: usize) -> Result<impl Buf<[Block; 2]>, Error> {
        let mut ots = HugePageMemory::zeroed(count);
        self.random_sent_into(count, &mut ots).await?;
        Ok(ots)
    }

    pub async fn random_sent_into(
        &mut self,
        count: usize,
        ots: &mut impl Buf<[Block; 2]>,
    ) -> Result<(), Error> {
        assert_eq!(count, ots.len());
        let delta = self.rng.random();
        let mut ots_buf = mem::take(ots);
        let correlated = self.correlated_send(count, delta).await?;

        let ots_buf = spawn_compute(move || {
            let masked_delta = delta & Block::MASK_LSB;
            for ((chunk_idx, ot_chunk), corr_chunk) in ots_buf
                .chunks_mut(AES_PAR_BLOCKS)
                .enumerate()
                .zip(correlated.chunks(AES_PAR_BLOCKS))
            {
                for (ots, corr) in ot_chunk.iter_mut().zip(corr_chunk) {
                    let masked = *corr & Block::MASK_LSB;
                    *ots = [masked, masked ^ masked_delta]
                }
                if S::MALICIOUS_SECURITY {
                    // It is currently unknown whether a cr hash is sufficient for Silent OT, so we
                    // use the safe choice of a tccr hash at the cost of some performance.
                    // See https://github.com/osu-crypto/libOTe/issues/166 for discussion
                    FIXED_KEY_HASH.tccr_hash_slice_mut(cast_slice_mut(ot_chunk), |i| {
                        Block::from(chunk_idx * AES_PAR_BLOCKS + i / 2)
                    });
                } else {
                    FIXED_KEY_HASH.cr_hash_slice_mut(cast_slice_mut(ot_chunk));
                }
            }
            ots_buf
        })
        .await
        .expect("worker panic");
        *ots = ots_buf;
        Ok(())
    }

    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_send"))]
    pub async fn correlated_send(
        &mut self,
        count: usize,
        delta: Block,
    ) -> Result<impl Buf<Block>, Error> {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        self.correlated_send_into(count, delta, &mut ots).await?;
        Ok(ots)
    }

    pub async fn correlated_send_into(
        &mut self,
        count: usize,
        delta: Block,
        ots: &mut impl Buf<Block>,
    ) -> Result<(), Error> {
        let mult_type = MultType::default();
        let conf = Config::configure(count, mult_type);
        let pprf_conf = PprfConfig::from(conf);
        assert!(
            ots.len() >= pprf_conf.size(),
            "ots Buf not big enough. Allocate at least Self::ots_buf_size"
        );

        let mal_check_ot_count = S::MALICIOUS_SECURITY as usize * SECURITY_PARAMETER;
        let base_ot_count = pprf_conf.base_ot_count().next_multiple_of(128) + mal_check_ot_count;

        // count must be divisable by 128 for ot_extension
        let mut base_ots = self.ot_sender.send(base_ot_count).await?;

        let mal_check_ots = base_ots.split_off(base_ot_count - mal_check_ot_count);

        base_ots.truncate(pprf_conf.base_ot_count());

        let pprf_sender =
            RegularPprfSender::new_with_conf(self.conn.sub_connection(), pprf_conf, base_ots);
        let mut B = mem::take(ots);
        pprf_sender
            .expand(delta, self.rng.random(), conf.pprf_out_fmt(), &mut B)
            .await?;

        if S::MALICIOUS_SECURITY {
            self.ferret_mal_check(delta, &mut B, mal_check_ots).await?;
        }

        let enc = Encoder::new(count, mult_type);
        *ots = enc.send_compress(B).await;
        Ok(())
    }

    async fn ferret_mal_check(
        &mut self,
        delta: Block,
        B: &mut impl Buf<Block>,
        mal_check_ots: Vec<[Block; 2]>,
    ) -> Result<(), Error> {
        assert_eq!(SECURITY_PARAMETER, mal_check_ots.len());
        let (mut tx, mut rx) = self.conn.request_response_stream().await?;
        let mal_check_seed: Block = rx.next().await.ok_or(Error::MissingReceiverSeed)??;

        let owned_B = mem::take(B);
        let jh = spawn_compute(move || {
            let mut xx = mal_check_seed;
            let (sum_low, sum_high) = owned_B.iter().fold(
                (Block::ZERO, Block::ZERO),
                |(mut sum_low, mut sum_high), b| {
                    let (low, high) = xx.clmul(b);
                    sum_low ^= low;
                    sum_high ^= high;
                    xx = xx.gf_mul(&mal_check_seed);
                    (sum_low, sum_high)
                },
            );
            (Block::gf_reduce(&sum_low, &sum_high), owned_B)
        });

        let mut receiver = NoisyVoleReceiver::new(self.conn.sub_connection());
        let a = receiver.receive(vec![delta], mal_check_ots).await?;

        let (my_sum, owned_B) = jh.await.expect("worker panic");
        *B = owned_B;

        let my_hash = (my_sum ^ a[0]).ro_hash();
        tx.send(my_hash).await?;

        Ok(())
    }
}

pub struct SilentOtReceiver<S> {
    conn: Connection,
    ot_receiver: OtExtensionReceiver<SemiHonestMarker>,
    rng: StdRng,
    s: PhantomData<S>,
}

impl<S: Security> SilentOtReceiver<S> {
    pub fn new(mut conn: Connection) -> Self {
        let ot_receiver = OtExtensionReceiver::new(conn.sub_connection());
        Self {
            conn,
            ot_receiver,
            rng: StdRng::from_os_rng(),
            s: PhantomData,
        }
    }

    // Needed minimum buffer size when using `receive_into` methods.
    pub fn ots_buf_size(count: usize) -> usize {
        let conf = Config::configure(count, MultType::default());
        let pprf_conf = PprfConfig::from(conf);
        pprf_conf.size()
    }

    pub async fn random_receive(
        &mut self,
        count: usize,
    ) -> Result<(impl Buf<Block>, Vec<Choice>), Error> {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        let choices = self.random_receive_into(count, &mut ots).await?;
        Ok((ots, choices))
    }

    pub async fn random_receive_into(
        &mut self,
        count: usize,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Error> {
        self.internal_correlated_receive_into(count, ChoiceBitPacking::Packed, ots)
            .await?;

        let mut ots_buf = mem::take(ots);
        let (ots_buf, choices) = spawn_compute(move || {
            let choices = ots_buf
                .iter_mut()
                .map(|block| {
                    let choice = Choice::from(block.lsb() as u8);
                    *block &= Block::MASK_LSB;
                    choice
                })
                .collect();

            if S::MALICIOUS_SECURITY {
                FIXED_KEY_HASH.tccr_hash_slice_mut(&mut ots_buf, Block::from);
            } else {
                FIXED_KEY_HASH.cr_hash_slice_mut(&mut ots_buf);
            }
            (ots_buf, choices)
        })
        .await
        .expect("worker panic");
        *ots = ots_buf;
        Ok(choices)
    }

    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_receive"))]
    pub async fn correlated_receive(
        &mut self,
        count: usize,
    ) -> Result<(impl Buf<Block>, Vec<Choice>), Error> {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        let choices = self.correlated_receive_into(count, &mut ots).await?;
        Ok((ots, choices))
    }

    #[tracing::instrument(target = "cryprot_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_receive"))]
    pub async fn correlated_receive_into(
        &mut self,
        count: usize,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Error> {
        self.internal_correlated_receive_into(count, ChoiceBitPacking::NotPacked, ots)
            .await
            .map(|cb| cb.expect("not choice packed"))
    }

    async fn internal_correlated_receive_into(
        &mut self,
        count: usize,
        cb_packing: ChoiceBitPacking,
        ots: &mut impl Buf<Block>,
    ) -> Result<Option<Vec<Choice>>, Error> {
        let mult_type = MultType::default();
        let conf = Config::configure(count, mult_type);
        let pprf_conf = PprfConfig::from(conf);
        assert_eq!(ots.len(), pprf_conf.size());

        let base_choices = pprf_conf.sample_choice_bits(&mut self.rng);
        let noisy_points = pprf_conf.get_points(conf.pprf_out_fmt(), &base_choices);

        let mut base_choices_subtle: Vec<_> =
            base_choices.iter().copied().map(Choice::from).collect();
        // we will discard these base OTs so we simply set the choice to 0. The ot
        // extension implementation can currently only handle num ots that are multiple
        // of 128
        base_choices_subtle.resize(
            pprf_conf.base_ot_count().next_multiple_of(128),
            Choice::from(0),
        );

        let mut mal_check_seed = Block::ZERO;
        let mut mal_check_x = Block::ZERO;
        if S::MALICIOUS_SECURITY {
            mal_check_seed = self.rng.random();

            for &p in &noisy_points {
                mal_check_x ^= mal_check_seed.gf_pow(p as u64 + 1);
            }
            base_choices_subtle.extend(mal_check_x.bits().map(|b| Choice::from(b as u8)));
        }

        let mut base_ots = self.ot_receiver.receive(&base_choices_subtle).await?;
        let mal_check_ots = base_ots
            .split_off(base_ots.len() - (S::MALICIOUS_SECURITY as usize * SECURITY_PARAMETER));

        base_ots.truncate(pprf_conf.base_ot_count());

        let pprf_receiver = RegularPprfReceiver::new_with_conf(
            self.conn.sub_connection(),
            pprf_conf,
            base_ots,
            base_choices,
        );
        let mut A = mem::take(ots);
        pprf_receiver.expand(conf.pprf_out_fmt(), &mut A).await?;

        if S::MALICIOUS_SECURITY {
            self.ferret_mal_check(&mut A, mal_check_seed, mal_check_x, mal_check_ots)
                .await?;
        }

        let enc = Encoder::new(count, mult_type);
        let (A, choices) = enc.receive_compress(A, noisy_points, cb_packing).await;
        *ots = A;
        Ok(choices)
    }

    async fn ferret_mal_check(
        &mut self,
        A: &mut impl Buf<Block>,
        mal_check_seed: Block,
        mal_check_x: Block,
        mal_check_ots: Vec<Block>,
    ) -> Result<(), Error> {
        assert_eq!(SECURITY_PARAMETER, mal_check_ots.len());
        let (mut tx, mut rx) = self.conn.request_response_stream().await?;
        tx.send(mal_check_seed).await?;

        let owned_A = mem::take(A);
        let jh = spawn_compute(move || {
            let mut xx = mal_check_seed;
            let (sum_low, sum_high) = owned_A.iter().fold(
                (Block::ZERO, Block::ZERO),
                |(mut sum_low, mut sum_high), a| {
                    let (low, high) = xx.clmul(a);
                    sum_low ^= low;
                    sum_high ^= high;
                    xx = xx.gf_mul(&mal_check_seed);
                    (sum_low, sum_high)
                },
            );
            (Block::gf_reduce(&sum_low, &sum_high), owned_A)
        });

        let mut sender = NoisyVoleSender::new(self.conn.sub_connection());
        let b = sender.send(1, mal_check_x, mal_check_ots).await?;

        let (my_sum, owned_A) = jh.await.expect("worker panic");
        *A = owned_A;

        let my_hash = (my_sum ^ b[0]).ro_hash();

        let their_hash: Hash = rx.next().await.ok_or(Error::MissingSenderHash)??;
        if my_hash != their_hash {
            return Err(Error::MaliciousCheck);
        }
        Ok(())
    }
}

impl SemiHonest for SilentOtSender<SemiHonestMarker> {}
impl SemiHonest for SilentOtReceiver<SemiHonestMarker> {}

impl SemiHonest for SilentOtSender<MaliciousMarker> {}
impl SemiHonest for SilentOtReceiver<MaliciousMarker> {}
impl Malicious for SilentOtSender<MaliciousMarker> {}
impl Malicious for SilentOtReceiver<MaliciousMarker> {}

impl<S> Connected for SilentOtSender<S> {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl<S: Security> RandChoiceRotSender for SilentOtSender<S> {}

impl<S: Security> RotSender for SilentOtSender<S> {
    type Error = Error;

    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        self.random_sent_into(ots.len(), ots).await?;
        Ok(())
    }
}

impl<S> Connected for SilentOtReceiver<S> {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl<S: Security> RandChoiceRotReceiver for SilentOtReceiver<S> {
    type Error = Error;

    async fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Self::Error> {
        let count = ots.len();
        ots.grow_zeroed(Self::ots_buf_size(count));
        let choices = self.random_receive_into(count, ots).await?;
        Ok(choices)
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
enum ChoiceBitPacking {
    #[default]
    Packed,
    NotPacked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Config {
    num_partitions: usize,
    size_per: usize,
    mult_type: MultType,
}

impl Config {
    fn configure(num_ots: usize, mult_type: MultType) -> Self {
        let min_dist = match mult_type {
            MultType::ExConv7x24 => 0.15,
            MultType::ExConv21x24 => 0.2,
        };
        let num_partitions = get_reg_noise_weight(min_dist, num_ots * SCALER, SECURITY_PARAMETER);
        let size_per = 4.max(
            (num_ots * SCALER)
                .div_ceil(num_partitions)
                .next_multiple_of(2),
        );

        Self {
            num_partitions,
            size_per,
            mult_type,
        }
    }

    fn pprf_out_fmt(&self) -> cryprot_pprf::OutFormat {
        cryprot_pprf::OutFormat::Interleaved
    }
}

impl From<Config> for PprfConfig {
    fn from(value: Config) -> Self {
        Self::new(value.size_per, value.num_partitions)
    }
}

struct Encoder {
    code: ExConvCode,
}

impl Encoder {
    fn new(num_ots: usize, mult_type: MultType) -> Self {
        let expander_weight = match mult_type {
            MultType::ExConv7x24 => 7,
            MultType::ExConv21x24 => 21,
        };
        let code = ExConvCode::new_with_conf(
            num_ots,
            ExConvCodeConfig {
                code_size: num_ots * SCALER,
                expander_weight,
                ..Default::default()
            },
        );
        assert_eq!(code.conf().accumulator_size, 24);
        Self { code }
    }

    async fn send_compress<B: Buf<Block>>(self, mut b: B) -> B {
        spawn_compute(move || {
            self.code.dual_encode(&mut b[..self.code.conf().code_size]);
            b.set_len(self.code.message_size());
            b
        })
        .await
        .expect("worker panic")
    }

    async fn receive_compress<B: Buf<Block>>(
        self,
        mut a: B,
        noisy_points: Vec<usize>,
        cb_packing: ChoiceBitPacking,
    ) -> (B, Option<Vec<Choice>>) {
        let jh = spawn_compute(move || {
            let (mut a, cb) = if cb_packing == ChoiceBitPacking::Packed {
                // Set lsb of noisy point idx to 1, all others to 0
                let mask_lsb = Block::ONES ^ Block::ONE;
                for block in a.iter_mut() {
                    *block &= mask_lsb;
                }

                for idx in noisy_points {
                    a[idx] |= Block::ONE
                }

                self.code.dual_encode(&mut a[..self.code.conf().code_size]);
                (a, None::<Vec<Choice>>)
            } else {
                self.code.dual_encode(&mut a[..self.code.conf().code_size]);
                let mut choices = vec![0_u8; self.code.conf().code_size];
                for idx in noisy_points {
                    if idx < choices.len() {
                        choices[idx] = 1;
                    }
                }
                self.code.dual_encode(&mut choices);
                let mut choices: Vec<_> = choices.into_iter().map(Choice::from).collect();
                choices.truncate(self.code.message_size());
                (a, Some(choices))
            };

            a.set_len(self.code.message_size());
            (a, cb)
        });
        jh.await.expect("worker panic")
    }
}

#[allow(non_snake_case)]
fn get_reg_noise_weight(min_dist_ratio: f64, N: usize, sec_param: usize) -> usize {
    assert!(min_dist_ratio <= 0.5 && min_dist_ratio > 0.0);
    let d = (1.0 - 2.0 * min_dist_ratio).log2();
    let mut t = 40.max((-(sec_param as f64) / d) as usize);
    if N < 512 {
        t = t.max(64);
    }
    t.next_multiple_of(cryprot_pprf::PARALLEL_TREES)
}

#[cfg(test)]
mod tests {
    use cryprot_core::Block;
    use cryprot_net::testing::{init_tracing, local_conn};
    use subtle::Choice;

    use crate::{
        RandChoiceRotReceiver, RotSender,
        silent_ot::{
            MaliciousSilentOtReceiver, MaliciousSilentOtSender, SemiHonestSilentOtReceiver,
            SemiHonestSilentOtSender,
        },
    };

    fn check_correlated(a: &[Block], b: &[Block], choice: Option<&[Choice]>, delta: Block) {
        {
            let n = a.len();
            assert_eq!(b.len(), n);
            if let Some(choice) = choice {
                assert_eq!(choice.len(), n)
            }
            let mask = if choice.is_some() {
                // don't mask off lsb when not using choice packing
                Block::ONES
            } else {
                // mask off lsb
                Block::ONES ^ Block::ONE
            };

            for i in 0..n {
                let m1 = a[i];
                let c = if let Some(choice) = choice {
                    choice[i].unwrap_u8() as usize
                } else {
                    // extract choice bit from m1
                    ((m1 & Block::ONE) == Block::ONE) as usize
                };
                let m1 = m1 & mask;
                let m2a = b[i] & mask;
                let m2b = (b[i] ^ delta) & mask;

                let eqq = [m1 == m2a, m1 == m2b];
                assert!(
                    eqq[c] && !eqq[c ^ 1],
                    "Blocks at {i} differ. Choice: {c} {m1:?}, {m2a:?}, {m2b:?}"
                );
                assert!(eqq[0] || eqq[1]);
            }
        }
    }

    fn check_random(count: usize, s_ot: &[[Block; 2]], r_ot: &[Block], c: &[Choice]) {
        assert_eq!(s_ot.len(), count);
        assert_eq!(r_ot.len(), count);
        assert_eq!(c.len(), count);

        for i in 0..count {
            assert_eq!(
                r_ot[i],
                s_ot[i][c[i].unwrap_u8() as usize],
                "Difference at OT {i}\nr_ot: {:?}\ns_ot: {:?}\nc: {}",
                r_ot[i],
                s_ot[i],
                c[i].unwrap_u8()
            );
        }
    }

    #[tokio::test]
    async fn correlated_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SemiHonestSilentOtSender::new(c1);
        let mut receiver = SemiHonestSilentOtReceiver::new(c2);
        let delta = Block::ONES;
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, choices)) = tokio::try_join!(
            sender.correlated_send(count, delta),
            receiver.correlated_receive(count)
        )
        .unwrap();

        assert_eq!(s_ot.len(), count);
        assert_eq!(r_ot.len(), count);

        check_correlated(&r_ot, &s_ot, Some(&choices), delta);
    }

    #[tokio::test]
    async fn random_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SemiHonestSilentOtSender::new(c1);
        let mut receiver = SemiHonestSilentOtReceiver::new(c2);
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, choices)) =
            tokio::try_join!(sender.random_send(count), receiver.random_receive(count)).unwrap();

        check_random(count, &s_ot, &r_ot[..], &choices);
    }

    #[tokio::test]
    async fn test_rot_trait_for_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SemiHonestSilentOtSender::new(c1);
        let mut receiver = SemiHonestSilentOtReceiver::new(c2);
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, c)) =
            tokio::try_join!(sender.send(count), receiver.rand_choice_receive(count)).unwrap();

        check_random(count, &s_ot, &r_ot, &c);
    }

    #[tokio::test]
    async fn test_malicious_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = MaliciousSilentOtSender::new(c1);
        let mut receiver = MaliciousSilentOtReceiver::new(c2);
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, choices)) =
            tokio::try_join!(sender.random_send(count), receiver.random_receive(count)).unwrap();

        check_random(count, &s_ot, &r_ot[..], &choices);
    }

    #[cfg(not(debug_assertions))]
    #[tokio::test]
    // This test, when run with RUST_LOG=info and --nocapture will print the
    // communication for 2^18 silent OTs
    async fn silent_ot_comm() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SemiHonestSilentOtSender::new(c1);
        let mut receiver = SemiHonestSilentOtReceiver::new(c2);
        let delta = Block::ONES;
        let count = 2_usize.pow(18);

        let (s_ot, (r_ot, choices)) = tokio::try_join!(
            sender.correlated_send(count, delta),
            receiver.correlated_receive(count, ChoiceBitPacking::Packed)
        )
        .unwrap();

        assert_eq!(s_ot.len(), count);

        check_correlated(&r_ot, &s_ot, choices.as_deref(), delta);
    }
}
