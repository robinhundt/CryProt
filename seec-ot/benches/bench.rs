use std::{thread, time::Duration};

use bitvec::bitvec;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use seec_core::test_utils::init_bench_tracing;
use seec_net::testing::local_conn;
use seec_ot::{
    base::SimplestOt,
    extension::{OtExtensionReceiver, OtExtensionSender},
    random_choices, RotReceiver, RotSender,
};
use tokio::{
    runtime::{self, Handle, Runtime},
    time,
};

fn criterion_benchmark(c: &mut Criterion) {
    init_bench_tracing();
    let rt = runtime::Builder::new_multi_thread()
        .worker_threads(2)
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
                let mut choices = random_choices(count, &mut rng1);
                let sender = SimplestOt::new_with_rng(c1.sub_connection(), rng1);
                let receiver = SimplestOt::new_with_rng(c2.sub_connection(), rng2);
                (sender, receiver, choices)
            },
            |(mut sender, mut receiver, choices)| async move {
                let t1 = tokio::spawn(async move { sender.send(count).await });
                let t2 = tokio::spawn(async move { receiver.receive(&choices).await });
                let (a, b) = tokio::try_join!(t1, t2).unwrap();
                a.unwrap();
                b.unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    let count = 2_usize.pow(24);
    c.bench_function("2**24 extension OTs", |b| {
        b.iter_batched(
            || {
                let mut rng1 = StdRng::seed_from_u64(42);
                let rng2 = StdRng::seed_from_u64(42 * 42);
                let mut choices = random_choices(count, &mut rng1);
                let mut sender = OtExtensionSender::new_with_rng(c1.sub_connection(), rng1);
                let mut receiver = OtExtensionReceiver::new_with_rng(c2.sub_connection(), rng2);
                let handle = rt.handle();
                thread::scope(|s| {
                    s.spawn(|| {
                        handle
                            .block_on(async {
                                tokio::try_join!(sender.do_base_ots(), receiver.do_base_ots())
                            })
                            .unwrap();
                    });
                });
                let rt1 = runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                let rt2 = runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();

                (sender, receiver, choices, rt1, rt2)
            },
            |(mut sender, mut receiver, choices, rt1, rt2)| {
                let (a, b) = thread::scope(|s| {
                    let a = s.spawn(|| rt1.block_on(sender.send(count)));
                    let b = s.spawn(|| rt2.block_on(receiver.receive(&choices)));
                    (a.join(), b.join())
                });
                // let t1 = tokio::spawn(async move { sender.send(count).await });
                // let t2 = tokio::spawn(async move { receiver.receive(&choices).await });
                // let (a, b) = tokio::try_join!(t1, t2).unwrap();
                a.unwrap().unwrap();
                b.unwrap().unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
