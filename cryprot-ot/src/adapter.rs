//! Adapters for OT types.

use bitvec::{order::Lsb0, vec::BitVec};
use futures::{SinkExt, StreamExt};

use crate::{Connected, RandChoiceRotReceiver, RandChoiceRotSender, RotReceiver, RotSender};

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

impl<R: RandChoiceRotReceiver> RotReceiver for ChosenChoice<R> {
    type Error = R::Error;

    async fn receive_into(
        &mut self,
        choices: &[subtle::Choice],
        ots: &mut impl cryprot_core::buf::Buf<cryprot_core::Block>,
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
