//! Adapters for OT types.

use bitvec::{order::Lsb0, vec::BitVec};
use cryprot_core::{Block, buf::Buf};
use cryprot_net::ConnectionError;
use futures::{SinkExt, StreamExt};
use subtle::ConditionallySelectable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Connected, CotReceiver, CotSender, Malicious, RandChoiceRotReceiver, RandChoiceRotSender,
    RotReceiver, RotSender, SemiHonest,
};

/// Adapts a [`RandChoiceRotReceiver`] into a [`RotReceiver`] and
/// [`RandChoiceRotSender`] into [`RotSender`].
///
/// This adapter can be used to adapt the [silent OT](`crate::silent_ot`)
/// protocol into a protocol with chosen choice bits at the cost number of OTs
/// bits of communication.
#[derive(Debug)]
pub struct ChosenChoice<P>(P);

impl<P> ChosenChoice<P> {
    pub fn new(ot_protocol: P) -> Self {
        Self(ot_protocol)
    }
}

impl<P: Connected> Connected for ChosenChoice<P> {
    fn connection(&mut self) -> &mut cryprot_net::Connection {
        self.0.connection()
    }
}

impl<P: SemiHonest> SemiHonest for ChosenChoice<P> {}

// TODO is there something I can cite that this holds?
impl<P: Malicious> Malicious for ChosenChoice<P> {}

impl<R: RandChoiceRotReceiver> RotReceiver for ChosenChoice<R> {
    type Error = R::Error;

    async fn receive_into(
        &mut self,
        ots: &mut impl cryprot_core::buf::Buf<cryprot_core::Block>,
        choices: &[subtle::Choice],
    ) -> Result<(), Self::Error> {
        let mut rand_choices = self
            .0
            .rand_choice_receive_into(ots)
            .await
            .map_err(|_| ())
            .unwrap();
        for (c1, c2) in rand_choices.iter_mut().zip(choices) {
            *c1 ^= *c2;
        }
        let mut bv: BitVec<u8, Lsb0> = BitVec::with_capacity(choices.len());
        bv.extend(rand_choices.iter().map(|c| c.unwrap_u8() != 0));

        let (mut tx, _) = self.connection().stream().await.unwrap();
        tx.send(bv).await.unwrap();
        Ok(())
    }
}

impl<S: RotSender + RandChoiceRotSender + Send> RotSender for ChosenChoice<S> {
    type Error = S::Error;

    async fn send_into(
        &mut self,
        ots: &mut impl cryprot_core::buf::Buf<[cryprot_core::Block; 2]>,
    ) -> Result<(), Self::Error> {
        self.0.send_into(ots).await.map_err(|_| ()).unwrap();
        let (_, mut rx) = self.connection().stream().await.unwrap();
        let correction: BitVec<u8, Lsb0> = rx.next().await.unwrap().unwrap();

        for (ots, c_bit) in ots.iter_mut().zip(correction) {
            let tmp = *ots;
            ots[0] = tmp[c_bit as usize];
            ots[1] = tmp[!c_bit as usize];
        }
        Ok(())
    }
}

/// Adapts any [`RotSender`]/[`RotReceiver`] into a
/// [`CotSender`]/[`CotReceiver`].
///
/// This adapter can also be used to easily implement the correlated OT traits
/// on the protocol types directly. Because `&mut S: RotSender` when `S:
/// RotSender` you can create a temporary [`CorrelatedFromRandom`] from a `&mut
/// self` inside an implementation of the correlated traits.
///
/// ```
/// use cryprot_core::{Block, buf::Buf};
///
/// use cryprot_ot::adapter::CorrelatedFromRandom;
/// use cryprot_ot::{Connected, CotSender, RotSender};
///
/// struct MyRotSender;
///
/// # impl Connected for MyRotSender {
/// #     fn connection(&mut self) -> &mut cryprot_net::Connection {
/// #         todo!()
/// #     }
/// # }
///
/// // Error type must implement `From<ConnectionError>` and `From<io::Error>` for
/// // adapter
/// #[derive(thiserror::Error, Debug)]
/// enum Error {
///     #[error("connection")]
///     Connection(#[from] cryprot_net::ConnectionError),
///     #[error("io")]
///     Io(#[from] std::io::Error),
/// }
///
/// impl RotSender for MyRotSender {
///     type Error = Error;
///
///     async fn send_into(
///         &mut self,
///         ots: &mut impl cryprot_core::buf::Buf<[cryprot_core::Block; 2]>,
///     ) -> Result<(), Self::Error> {
///         todo!()
///     }
/// }
///
/// impl CotSender for MyRotSender {
///     type Error = <MyRotSender as RotSender>::Error;
///
///     async fn correlated_send_into<B, F>(
///         &mut self,
///         ots: &mut B,
///         correlation: F,
///     ) -> Result<(), Self::Error>
///     where
///         B: Buf<Block>,
///         F: FnMut(usize) -> Block + Send,
///     {
///         // because &mut self also implements RotSender, we can use it for the adapter
///         CorrelatedFromRandom::new(self)
///             .correlated_send_into(ots, correlation)
///             .await
///     }
/// }
/// ```
#[derive(Debug)]
pub struct CorrelatedFromRandom<P>(P);

impl<P> CorrelatedFromRandom<P> {
    pub fn new(protocol: P) -> Self {
        Self(protocol)
    }
}

impl<P: Connected> Connected for CorrelatedFromRandom<P> {
    fn connection(&mut self) -> &mut cryprot_net::Connection {
        self.0.connection()
    }
}

impl<P: SemiHonest> SemiHonest for CorrelatedFromRandom<P> {}

// For a discussion of the security of this see https://github.com/osu-crypto/libOTe/issues/167
impl<P: Malicious> Malicious for CorrelatedFromRandom<P> {}

// should fit in one jumbo frame
const COR_CHUNK_SIZE: usize = 8500 / Block::BYTES;

impl<S: RotSender> CotSender for CorrelatedFromRandom<S>
where
    S::Error: From<ConnectionError> + From<std::io::Error>,
{
    type Error = S::Error;

    async fn correlated_send_into<B, F>(
        &mut self,
        ots: &mut B,
        mut correlation: F,
    ) -> Result<(), Self::Error>
    where
        B: Buf<Block>,
        F: FnMut(usize) -> Block + Send,
    {
        let mut r_ots: B::BufKind<[Block; 2]> = B::BufKind::zeroed(ots.len());
        self.0.send_into(&mut r_ots).await?;
        let mut send_buf: Vec<Block> = Vec::zeroed(COR_CHUNK_SIZE);
        let (mut tx, _) = self.connection().byte_stream().await?;
        // Using spawn_compute here results in slightly lower performance.
        // I think there is just not enough work done per byte transmitted here.
        // This implementation is also simpler and less prone to errors than the
        // spawn_compute one.
        for (chunk_idx, (ot_chunk, rot_chunk)) in ots
            .chunks_mut(send_buf.len())
            .zip(r_ots.chunks(send_buf.len()))
            .enumerate()
        {
            for (idx, ((ot, r_ot), correction)) in ot_chunk
                .iter_mut()
                .zip(rot_chunk)
                .zip(&mut send_buf)
                .enumerate()
            {
                *ot = r_ot[0];
                *correction = r_ot[1] ^ r_ot[0] ^ correlation(chunk_idx * COR_CHUNK_SIZE + idx);
            }
            tx.write_all(bytemuck::must_cast_slice_mut(
                &mut send_buf[..ot_chunk.len()],
            ))
            .await?;
        }
        Ok(())
    }
}

impl<R: RotReceiver> CotReceiver for CorrelatedFromRandom<R>
where
    R::Error: From<ConnectionError> + From<std::io::Error>,
{
    type Error = R::Error;

    async fn correlated_receive_into<B>(
        &mut self,
        ots: &mut B,
        choices: &[subtle::Choice],
    ) -> Result<(), Self::Error>
    where
        B: Buf<Block>,
    {
        self.0.receive_into(ots, choices).await?;
        let mut recv_buf: Vec<Block> = Vec::zeroed(COR_CHUNK_SIZE);
        let (_, mut rx) = self.connection().byte_stream().await?;
        for (ot_chunk, choice_chunk) in ots
            .chunks_mut(COR_CHUNK_SIZE)
            .zip(choices.chunks(COR_CHUNK_SIZE))
        {
            rx.read_exact(bytemuck::must_cast_slice_mut(
                &mut recv_buf[..ot_chunk.len()],
            ))
            .await?;
            for ((ot, correction), choice) in ot_chunk.iter_mut().zip(&recv_buf).zip(choice_chunk) {
                let use_correction = Block::conditional_select(&Block::ZERO, &Block::ONES, *choice);
                *ot ^= use_correction & *correction;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cryprot_net::testing::{init_tracing, local_conn};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        RotReceiver, RotSender,
        adapter::ChosenChoice,
        random_choices,
        silent_ot::{SemiHonestSilentOtReceiver, SemiHonestSilentOtSender},
    };

    #[tokio::test]
    async fn test_chosen_choice_adapter() {
        let _g = init_tracing();
        let (c1, c2) = local_conn().await.unwrap();
        let mut sender = ChosenChoice::new(SemiHonestSilentOtSender::new(c1));
        let mut receiver = ChosenChoice::new(SemiHonestSilentOtReceiver::new(c2));

        let count = 2_usize.pow(10);
        let choices = random_choices(count, &mut StdRng::seed_from_u64(234));

        let (s_ots, r_ots) =
            tokio::try_join!(sender.send(count), receiver.receive(&choices)).unwrap();

        for (i, c) in choices.iter().enumerate() {
            assert_eq!(
                s_ots[i][c.unwrap_u8() as usize],
                r_ots[i],
                "ot {i}, choice: {}, s_ots: {:?}, r_ot: {:?}",
                c.unwrap_u8(),
                s_ots[i],
                r_ots[i]
            );
        }
    }
}
