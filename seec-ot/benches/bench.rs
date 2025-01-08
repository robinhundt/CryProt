use bitvec::bitvec;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use seec_core::test_utils::init_bench_tracing;
use seec_net::testing::local_conn;
use seec_ot::{base::SimplestOt, RotReceiver, RotSender};

fn criterion_benchmark(c: &mut Criterion) {
    init_bench_tracing();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut c1, mut c2) = rt.block_on(local_conn()).unwrap();

    let count = 128;

    c.bench_function("128 base OT", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let mut rng1 = StdRng::seed_from_u64(42);
                let rng2 = StdRng::seed_from_u64(42 * 42);
                let mut choices = bitvec!(0; count);
                rng1.fill(choices.as_raw_mut_slice());

                let sender = SimplestOt::new_with_rng(c1.sub_connection(), rng1);
                let receiver = SimplestOt::new_with_rng(c2.sub_connection(), rng2);
                (sender, receiver, choices)
            },
            |(mut sender, mut receiver, choices)| async move {
                tokio::try_join!(sender.send(count), receiver.receive(&choices)).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
