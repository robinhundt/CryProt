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

fn create_mt_runtime(threads: usize) -> Runtime {
    runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    init_bench_tracing();
    let rt = create_mt_runtime(8);
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

    let rt1 = create_mt_runtime(2);
    let rt2 = create_mt_runtime(2);

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
                (sender, receiver, choices)
            },
            |(mut sender, mut receiver, choices)| {
                let (a, b) = thread::scope(|s| {
                    let a = s.spawn(|| rt1.block_on(sender.send(count)));
                    let b = s.spawn(|| rt2.block_on(receiver.receive(&choices)));
                    (a.join(), b.join())
                });
                let send_ots = a.unwrap().unwrap();
                let recv_ots = b.unwrap().unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    let rt3 = create_mt_runtime(2);
    let rt4 = create_mt_runtime(2);

    let count = 2_usize.pow(24);
    c.bench_function("2 parallel 2**24 extension OTs", |b| {
        b.iter_batched(
            || {
                let mut rng1 = StdRng::seed_from_u64(42);
                let rng2 = StdRng::seed_from_u64(42 * 42);
                let mut choices = random_choices(count, &mut rng1);
                let mut sender1 =
                    OtExtensionSender::new_with_rng(c1.sub_connection(), rng1.clone());
                let mut receiver1 =
                    OtExtensionReceiver::new_with_rng(c2.sub_connection(), rng2.clone());

                let mut sender2 = OtExtensionSender::new_with_rng(c1.sub_connection(), rng1);
                let mut receiver2 = OtExtensionReceiver::new_with_rng(c2.sub_connection(), rng2);

                let handle = rt.handle();
                thread::scope(|s| {
                    s.spawn(|| {
                        handle
                            .block_on(async {
                                tokio::try_join!(
                                    sender1.do_base_ots(),
                                    receiver1.do_base_ots(),
                                    sender2.do_base_ots(),
                                    receiver2.do_base_ots()
                                )
                            })
                            .unwrap();
                    });
                });
                (sender1, receiver1, sender2, receiver2, choices)
            },
            |(mut sender1, mut receiver1, mut sender2, mut receiver2, choices)| {
                // TOOD why does multiple rts not work but one rt does?
                thread::scope(|s| {
                    s.spawn(|| rt1.block_on(sender1.send(count)));
                    s.spawn(|| rt2.block_on(receiver1.receive(&choices)));
                    s.spawn(|| rt3.block_on(sender2.send(count)));
                    s.spawn(|| rt4.block_on(receiver2.receive(&choices)));
                });
                // rt.block_on(async {
                //     tokio::try_join!(
                //         sender1.send(count),
                //         receiver1.receive(&choices),
                //         sender2.send(count),
                //         receiver2.receive(&choices),
                //     )
                //     .unwrap();
                // })
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
