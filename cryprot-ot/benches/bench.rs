use std::{
    env,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use cryprot_core::{alloc::HugePageMemory, Block};
use cryprot_net::testing::{init_bench_tracing, local_conn};
use cryprot_ot::{
    base::SimplestOt,
    extension::{
        MaliciousOtExtensionReceiver, MaliciousOtExtensionSender, SemiHonestOtExtensionReceiver,
        SemiHonestOtExtensionSender,
    },
    random_choices,
    silent_ot::{
        MaliciousSilentOtReceiver, MaliciousSilentOtSender, SemiHonestSilentOtReceiver,
        SemiHonestSilentOtSender,
    },
    RotReceiver, RotSender,
};
use rand::{rngs::StdRng, SeedableRng};
use tokio::runtime::{self, Runtime};

fn create_mt_runtime(threads: usize) -> Runtime {
    runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
}

fn get_var_size(var: &str, default: u32) -> u32 {
    env::var(var)
        .map(|s| s.parse().expect("not a number"))
        .unwrap_or(default)
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
                let choices = random_choices(count, &mut rng1);
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

    let p = get_var_size("CRYPROT_BENCH_OT_POWER", 24);
    let count = 2_usize.pow(p);
    let mut g = c.benchmark_group("semi-honest OT extension");
    g.sample_size(10);
    g.throughput(criterion::Throughput::Elements(count as u64));
    g.bench_function(format!("single 2**{p} extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let mut c11 = c1.sub_connection();
            let mut c22 = c2.sub_connection();

            async move {
                let mut duration = Duration::ZERO;
                let mut sender_ots = HugePageMemory::zeroed(count);
                let mut receiver_ots = HugePageMemory::zeroed(count);
                for _ in 0..iters {
                    // setup not included in duration
                    let (mut sender, mut receiver, choices) = {
                        let mut rng1 = StdRng::seed_from_u64(42);
                        let rng2 = StdRng::seed_from_u64(42 * 42);
                        let choices = random_choices(count, &mut rng1);
                        let mut sender =
                            SemiHonestOtExtensionSender::new_with_rng(c11.sub_connection(), rng1);
                        let mut receiver =
                            SemiHonestOtExtensionReceiver::new_with_rng(c22.sub_connection(), rng2);
                        tokio::try_join!(sender.do_base_ots(), receiver.do_base_ots()).unwrap();
                        (sender, receiver, choices)
                    };
                    let now = Instant::now();
                    (sender_ots, receiver_ots) = tokio::try_join!(
                        tokio::spawn(async move {
                            sender.send_into(&mut sender_ots).await.unwrap();
                            sender_ots
                        }),
                        tokio::spawn(async move {
                            receiver
                                .receive_into(&choices, &mut receiver_ots)
                                .await
                                .unwrap();
                            receiver_ots
                        })
                    )
                    .unwrap();
                    duration += now.elapsed();
                }
                duration
            }
        })
    });

    g.bench_function(format!("2 parallel 2**{p} extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let mut c11 = c1.sub_connection();
            let mut c22 = c2.sub_connection();
            async move {
                let mut duration = Duration::ZERO;
                for _ in 0..iters {
                    let (
                        mut sender1,
                        mut receiver1,
                        mut sender2,
                        mut receiver2,
                        choices1,
                        choices2,
                    ) = {
                        let mut rng1 = StdRng::seed_from_u64(42);
                        let mut rng2 = StdRng::seed_from_u64(42 * 42);
                        let choices1 = random_choices(count, &mut rng1);
                        let choices2 = random_choices(count, &mut rng2);
                        let mut sender1 = SemiHonestOtExtensionSender::new_with_rng(
                            c11.sub_connection(),
                            rng1.clone(),
                        );
                        let mut receiver1 = SemiHonestOtExtensionReceiver::new_with_rng(
                            c22.sub_connection(),
                            rng2.clone(),
                        );

                        let mut sender2 =
                            SemiHonestOtExtensionSender::new_with_rng(c11.sub_connection(), rng1);
                        let mut receiver2 =
                            SemiHonestOtExtensionReceiver::new_with_rng(c22.sub_connection(), rng2);

                        tokio::try_join!(
                            sender1.do_base_ots(),
                            receiver1.do_base_ots(),
                            sender2.do_base_ots(),
                            receiver2.do_base_ots()
                        )
                        .unwrap();
                        (sender1, receiver1, sender2, receiver2, choices1, choices2)
                    };
                    let now = Instant::now();
                    let jh1 = tokio::spawn(async move { sender1.send(count).await });
                    let jh2 = tokio::spawn(async move { receiver1.receive(&choices1).await });
                    let jh3 = tokio::spawn(async move { sender2.send(count).await });
                    let jh4 = tokio::spawn(async move { receiver2.receive(&choices2).await });
                    let (ot1, ot2, ot3, ot4) = tokio::try_join!(jh1, jh2, jh3, jh4).unwrap();
                    duration += now.elapsed();
                    ot1.unwrap();
                    ot2.unwrap();
                    ot3.unwrap();
                    ot4.unwrap();
                }
                duration
            }
        })
    });
    g.finish();

    let mut g = c.benchmark_group("malicious OT extension");
    g.sample_size(10);
    g.throughput(criterion::Throughput::Elements(count as u64));
    g.bench_function(format!("single 2**{p} extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let mut c11 = c1.sub_connection();
            let mut c22 = c2.sub_connection();

            async move {
                let mut duration = Duration::ZERO;
                let mut sender_ots = HugePageMemory::zeroed(count);
                let mut receiver_ots = HugePageMemory::zeroed(count);
                for _ in 0..iters {
                    // setup not included in duration
                    let (mut sender, mut receiver, choices) = {
                        let mut rng1 = StdRng::seed_from_u64(42);
                        let rng2 = StdRng::seed_from_u64(42 * 42);
                        let choices = random_choices(count, &mut rng1);
                        let mut sender =
                            MaliciousOtExtensionSender::new_with_rng(c11.sub_connection(), rng1);
                        let mut receiver =
                            MaliciousOtExtensionReceiver::new_with_rng(c22.sub_connection(), rng2);
                        tokio::try_join!(sender.do_base_ots(), receiver.do_base_ots()).unwrap();
                        (sender, receiver, choices)
                    };
                    let now = Instant::now();
                    (sender_ots, receiver_ots) = tokio::try_join!(
                        tokio::spawn(async move {
                            sender.send_into(&mut sender_ots).await.unwrap();
                            sender_ots
                        }),
                        tokio::spawn(async move {
                            receiver
                                .receive_into(&choices, &mut receiver_ots)
                                .await
                                .unwrap();
                            receiver_ots
                        })
                    )
                    .unwrap();
                    duration += now.elapsed();
                }
                duration
            }
        })
    });
    g.finish();

    let mut g = c.benchmark_group("silent extension");
    let p = get_var_size("CRYPROT_BENCH_SILENT_OT_POWER", 21);
    let count = 2_usize.pow(p);
    g.sample_size(10);
    g.throughput(criterion::Throughput::Elements(count as u64));
    g.bench_function(format!("2**{p} correlated extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let c11 = c1.sub_connection();
            let c22 = c2.sub_connection();

            async move {
                let mut duration = Duration::ZERO;
                // setup not included in duration
                let mut sender = SemiHonestSilentOtSender::new(c11);
                let mut receiver = SemiHonestSilentOtReceiver::new(c22);
                for _ in 0..iters {
                    let now = Instant::now();
                    (sender, receiver) = tokio::try_join!(
                        tokio::spawn(async move {
                            sender.correlated_send(count, Block::ONES).await.unwrap();
                            sender
                        }),
                        tokio::spawn(async move {
                            receiver.correlated_receive(count).await.unwrap();
                            receiver
                        })
                    )
                    .unwrap();
                    duration += now.elapsed();
                }
                duration
            }
        })
    });

    g.bench_function(format!("2**{p} random extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let c11 = c1.sub_connection();
            let c22 = c2.sub_connection();

            async move {
                let mut duration = Duration::ZERO;
                // setup not included in duration
                let mut sender = SemiHonestSilentOtSender::new(c11);
                let mut receiver = SemiHonestSilentOtReceiver::new(c22);
                for _ in 0..iters {
                    let now = Instant::now();
                    (sender, receiver) = tokio::try_join!(
                        tokio::spawn(async move {
                            sender.random_send(count).await.unwrap();
                            sender
                        }),
                        tokio::spawn(async move {
                            receiver.random_receive(count).await.unwrap();
                            receiver
                        })
                    )
                    .unwrap();
                    duration += now.elapsed();
                }
                duration
            }
        })
    });

    g.bench_function(format!("2**{p} malicious random extension OTs"), |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let c11 = c1.sub_connection();
            let c22 = c2.sub_connection();

            async move {
                let mut duration = Duration::ZERO;
                // setup not included in duration
                let mut sender = MaliciousSilentOtSender::new(c11);
                let mut receiver = MaliciousSilentOtReceiver::new(c22);
                for _ in 0..iters {
                    let now = Instant::now();
                    (sender, receiver) = tokio::try_join!(
                        tokio::spawn(async move {
                            sender.random_send(count).await.unwrap();
                            sender
                        }),
                        tokio::spawn(async move {
                            receiver.random_receive(count).await.unwrap();
                            receiver
                        })
                    )
                    .unwrap();
                    duration += now.elapsed();
                }
                duration
            }
        })
    });

    g.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
