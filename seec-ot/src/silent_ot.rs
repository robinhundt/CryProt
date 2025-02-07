#![allow(non_snake_case)]
use std::mem;

use bytemuck::cast_slice_mut;
use rand::{rngs::StdRng, Rng, SeedableRng};
use seec_codes::ex_conv::{ExConvCode, ExConvCodeConfig};
use seec_core::{
    aes_hash::FIXED_KEY_HASH, alloc::HugePageMemory, buf::Buf, tokio_rayon::spawn_compute, Block,
    AES_PAR_BLOCKS,
};
use seec_net::Connection;
use seec_pprf::{PprfConfig, RegularPprfReceiver, RegularPprfSender};
use subtle::Choice;
use tracing::Level;

use crate::{
    extension::{OtExtensionReceiver, OtExtensionSender}, Connected, RandChoiceRotReceiver, RandChoiceRotSender, RotReceiver, RotSender
};

pub const SECURITY_PARAMETER: usize = 128;
const SCALER: usize = 2;

pub struct SilentOtSender {
    conn: Connection,
    ot_sender: OtExtensionSender,
    rng: StdRng,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MultType {
    #[default]
    ExConv7x24,
    ExConv21x24,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChoiceBitPacking {
    #[default]
    Packed,
    NotPacked,
}

impl SilentOtSender {
    pub fn new(mut conn: Connection) -> Self {
        let ot_sender = OtExtensionSender::new(conn.sub_connection());
        Self {
            conn,
            ot_sender,
            rng: StdRng::from_entropy(),
        }
    }

    // Needed minimum buffer size when using `correlated_send_into` method.
    pub fn ots_buf_size(count: usize) -> usize {
        let conf = Config::configure(count, MultType::default());
        let pprf_conf = PprfConfig::from(conf);
        pprf_conf.size()
    }

    pub async fn random_send(&mut self, count: usize) -> impl Buf<[Block; 2]> {
        let mut ots = HugePageMemory::zeroed(count);
        self.random_sent_into(count, &mut ots).await;
        ots
    }

    pub async fn random_sent_into(&mut self, count: usize, ots: &mut impl Buf<[Block; 2]>) {
        assert_eq!(count, ots.len());
        let delta = self.rng.gen();
        let mut ots_buf = mem::take(ots);
        let correlated = self.correlated_send(count, delta).await;

        let ots_buf = spawn_compute(move || {
            let masked_delta = delta & Block::MASK_LSB;
            for (ot_chunk, corr_chunk) in ots_buf
                .chunks_mut(AES_PAR_BLOCKS)
                .zip(correlated.chunks(AES_PAR_BLOCKS))
            {
                for (ots, corr) in ot_chunk.iter_mut().zip(corr_chunk) {
                    let masked = *corr & Block::MASK_LSB;
                    *ots = [masked, masked ^ masked_delta]
                }
                FIXED_KEY_HASH.cr_hash_slice_mut(cast_slice_mut(ot_chunk));
            }
            ots_buf
        })
        .await;
        *ots = ots_buf;
    }

    #[tracing::instrument(target = "seec_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_send"))]
    pub async fn correlated_send(&mut self, count: usize, delta: Block) -> impl Buf<Block> {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        self.correlated_send_into(count, delta, &mut ots).await;
        ots
    }

    pub async fn correlated_send_into(
        &mut self,
        count: usize,
        delta: Block,
        ots: &mut impl Buf<Block>,
    ) {
        let mult_type = MultType::default();
        let conf = Config::configure(count, mult_type);
        let pprf_conf = PprfConfig::from(conf);
        assert!(
            ots.len() >= pprf_conf.size(),
            "ots Buf not big enough. Allocate at least Self::ots_buf_size"
        );

        let mut base_ots = self
            .ot_sender
            .send(pprf_conf.base_ot_count().next_multiple_of(128))
            .await
            .unwrap();
        base_ots.truncate(pprf_conf.base_ot_count());

        let pprf_sender =
            RegularPprfSender::new_with_conf(self.conn.sub_connection(), pprf_conf, base_ots);
        let mut B = mem::take(ots);
        pprf_sender
            .expand(delta, self.rng.gen(), conf.pprf_out_fmt(), &mut B)
            .await;

        let enc = Encoder::new(count, mult_type);
        *ots = enc.send_compress(B).await;
    }
}

pub struct SilentOtReceiver {
    conn: Connection,
    ot_receiver: OtExtensionReceiver,
    rng: StdRng,
}

impl SilentOtReceiver {
    pub fn new(mut conn: Connection) -> Self {
        let ot_receiver = OtExtensionReceiver::new(conn.sub_connection());
        Self {
            conn,
            ot_receiver,
            rng: StdRng::from_entropy(),
        }
    }

    // Needed minimum buffer size when using `receive_into` methods.
    pub fn ots_buf_size(count: usize) -> usize {
        let conf = Config::configure(count, MultType::default());
        let pprf_conf = PprfConfig::from(conf);
        pprf_conf.size()
    }

    pub async fn random_receive(&mut self, count: usize) -> (impl Buf<Block>, Vec<Choice>) {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        let choices = self.random_receive_into(count, &mut ots).await;
        (ots, choices)
    }

    pub async fn random_receive_into(
        &mut self,
        count: usize,
        ots: &mut impl Buf<Block>,
    ) -> Vec<Choice> {
        self.correlated_receive_into(count, ChoiceBitPacking::Packed, ots)
            .await;

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

            FIXED_KEY_HASH.cr_hash_slice_mut(&mut ots_buf);
            (ots_buf, choices)
        })
        .await;
        *ots = ots_buf;
        choices
    }

    #[tracing::instrument(target = "seec_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_receive"))]
    pub async fn correlated_receive(
        &mut self,
        count: usize,
        cb_packing: ChoiceBitPacking,
    ) -> (impl Buf<Block>, Option<Vec<Choice>>) {
        let mut ots = HugePageMemory::zeroed(Self::ots_buf_size(count));
        let choices = self
            .correlated_receive_into(count, cb_packing, &mut ots)
            .await;
        (ots, choices)
    }

    #[tracing::instrument(target = "seec_metrics", level = Level::TRACE, skip_all, fields(phase = "correlated_receive"))]
    pub async fn correlated_receive_into(
        &mut self,
        count: usize,
        cb_packing: ChoiceBitPacking,
        ots: &mut impl Buf<Block>,
    ) -> Option<Vec<Choice>> {
        let mult_type = MultType::default();
        let conf = Config::configure(count, mult_type);
        let pprf_conf = PprfConfig::from(conf);
        assert_eq!(ots.len(), pprf_conf.size());

        let base_choices = RegularPprfReceiver::sample_choice_bits(pprf_conf, &mut self.rng);
        let mut base_choices_subtle: Vec<_> =
            base_choices.iter().copied().map(Choice::from).collect();
        // we will discard these base OTs so we simply set the choice to 0. The ot
        // extension implementation can currently only handle num ots that are multiple
        // of 128
        base_choices_subtle.resize(
            pprf_conf.base_ot_count().next_multiple_of(128),
            Choice::from(0),
        );

        let mut base_ots = self
            .ot_receiver
            .receive(&base_choices_subtle)
            .await
            .unwrap();
        base_ots.truncate(pprf_conf.base_ot_count());

        let pprf_receiver = RegularPprfReceiver::new_with_conf(
            self.conn.sub_connection(),
            pprf_conf,
            base_ots,
            base_choices,
        );
        let noisy_points = pprf_receiver.get_points(conf.pprf_out_fmt());
        let mut A = mem::take(ots);
        pprf_receiver.expand(conf.pprf_out_fmt(), &mut A).await;

        let enc = Encoder::new(count, mult_type);
        let (A, choices) = enc.receive_compress(A, noisy_points, cb_packing).await;
        *ots = A;
        choices
    }
}

impl Connected for SilentOtSender {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl RandChoiceRotSender for SilentOtSender {}

impl RotSender for SilentOtSender {
    type Error = ();

    async fn send_into(&mut self, ots: &mut impl Buf<[Block; 2]>) -> Result<(), Self::Error> {
        self.random_sent_into(ots.len(), ots).await;
        Ok(())
    }
}

impl Connected for SilentOtReceiver {
    fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl RandChoiceRotReceiver for SilentOtReceiver {
    type Error = ();

    async fn rand_choice_receive_into(
        &mut self,
        ots: &mut impl Buf<Block>,
    ) -> Result<Vec<Choice>, Self::Error> {
        let count = ots.len();
        ots.grow_zeroed(Self::ots_buf_size(count));
        let choices = self.random_receive_into(count, ots).await;
        Ok(choices)
    }
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

    fn pprf_out_fmt(&self) -> seec_pprf::OutFormat {
        seec_pprf::OutFormat::Interleaved
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
    }

    async fn receive_compress<B: Buf<Block>>(
        self,
        mut a: B,
        noisy_points: Vec<usize>,
        cb_packing: ChoiceBitPacking,
    ) -> (B, Option<Vec<Choice>>) {
        spawn_compute(move || {
            let (mut a, mut cb) = if cb_packing == ChoiceBitPacking::Packed {
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
                todo!()
            };

            a.set_len(self.code.message_size());
            if let Some(cb) = &mut cb {
                cb.truncate(self.code.message_size());
            }
            (a, cb)
        })
        .await
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
    t.next_multiple_of(seec_pprf::PARALLEL_TREES)
}

#[cfg(test)]
mod tests {
    use seec_core::Block;
    use seec_net::testing::{init_tracing, local_conn};
    use subtle::Choice;

    use crate::{
        silent_ot::{ChoiceBitPacking, SilentOtReceiver, SilentOtSender},
        RandChoiceRotReceiver, RotSender,
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

        let mut sender = SilentOtSender::new(c1);
        let mut receiver = SilentOtReceiver::new(c2);
        let delta = Block::ONES;
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, choices)) = tokio::join!(
            sender.correlated_send(count, delta),
            receiver.correlated_receive(count, ChoiceBitPacking::Packed)
        );

        assert_eq!(s_ot.len(), count);
        assert_eq!(r_ot.len(), count);

        check_correlated(&r_ot, &s_ot, choices.as_deref(), delta);
    }

    #[tokio::test]
    async fn random_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SilentOtSender::new(c1);
        let mut receiver = SilentOtReceiver::new(c2);
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, choices)) =
            tokio::join!(sender.random_send(count), receiver.random_receive(count));

        check_random(count, &s_ot, &r_ot[..], &choices);
    }

    #[tokio::test]
    async fn test_rot_trait_for_silent_ot() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SilentOtSender::new(c1);
        let mut receiver = SilentOtReceiver::new(c2);
        let count = 2_usize.pow(11);

        let (s_ot, (r_ot, c)) =
            tokio::try_join!(sender.send(count), receiver.rand_choice_receive(count)).unwrap();

        check_random(count, &s_ot, &r_ot, &c);
    }

    #[cfg(not(debug_assertions))]
    #[tokio::test]
    // This test, when run with RUST_LOG=info and --nocapture will print the
    // communication for 2^18 silent OTs
    async fn silent_ot_comm() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();

        let mut sender = SilentOtSender::new(c1);
        let mut receiver = SilentOtReceiver::new(c2);
        let delta = Block::ONES;
        let count = 2_usize.pow(18);

        let (s_ot, (r_ot, choices)) = tokio::join!(
            sender.correlated_send(count, delta),
            receiver.correlated_receive(count, ChoiceBitPacking::Packed)
        );

        assert_eq!(s_ot.len(), count);

        check_correlated(&r_ot, &s_ot, choices.as_deref(), delta);
    }
}
