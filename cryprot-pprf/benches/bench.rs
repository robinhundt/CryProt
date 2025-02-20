use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use cryprot_core::{
    Block,
    alloc::{HugePageMemory, allocate_zeroed_vec},
};
use cryprot_net::testing::{init_bench_tracing, local_conn};
use cryprot_pprf::{
    OutFormat, PARALLEL_TREES, PprfConfig, RegularPprfReceiver, RegularPprfSender, fake_base,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::runtime::{self, Runtime};

fn create_mt_runtime(threads: usize) -> Runtime {
    runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    init_bench_tracing();
    let rt = create_mt_runtime(8);
    let (mut c1, mut c2) = rt.block_on(local_conn()).unwrap();

    let mut g = c.benchmark_group("pprf");
    g.sample_size(10).bench_function("pprf for 2**24 OTs", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let conf = conf(2_u64.pow(24));
                let mut rng = StdRng::seed_from_u64(42);

                let (sender_base_ots, receiver_base_ots, base_choices) = fake_base(conf, &mut rng);

                let sender =
                    RegularPprfSender::new_with_conf(c1.sub_connection(), conf, sender_base_ots);
                let receiver = RegularPprfReceiver::new_with_conf(
                    c2.sub_connection(),
                    conf,
                    receiver_base_ots,
                    base_choices,
                );
                let out1 = HugePageMemory::zeroed(conf.size());
                let out2 = HugePageMemory::zeroed(conf.size());
                let seed = rng.r#gen();
                (sender, receiver, seed, out1, out2)
            },
            |(sender, receiver, seed, mut out1, mut out2)| async move {
                let t1 = tokio::spawn(async move {
                    sender
                        .expand(Block::ONES, seed, OutFormat::Interleaved, &mut out1)
                        .await
                });
                let t2 = tokio::spawn(async move {
                    receiver.expand(OutFormat::Interleaved, &mut out2).await
                });
                tokio::try_join!(t1, t2).unwrap();
            },
            BatchSize::LargeInput,
        )
    });
    drop(g);

    let mut g = c.benchmark_group("aes");
    let conf = conf(2_u64.pow(24));
    let depth = conf.depth();
    let mut buf = allocate_zeroed_vec::<[Block; PARALLEL_TREES]>(2_usize.pow(depth as u32));
    let aes = Aes128::new_from_slice(&[42; 16]).unwrap();
    g.throughput(criterion::Throughput::Bytes(
        (buf.len() * 16 * conf.pnt_count()) as u64,
    ))
    .bench_function("enc speed", |b| {
        b.iter(|| {
            for _ in (0..conf.pnt_count()).step_by(PARALLEL_TREES) {
                for d in 0..depth - 1 {
                    let (lvl0, lvl1) = get_cons_levels(&mut buf, d);
                    for idx in 0..lvl1.len() {
                        let parent_idx = idx >> 1;
                        aes.encrypt_blocks_b2b(
                            bytemuck::cast_slice(&lvl0[parent_idx]),
                            bytemuck::cast_slice_mut(&mut lvl1[idx]),
                        )
                        .unwrap();
                    }
                }
            }
        });
    });
}

#[allow(non_snake_case)]
fn get_reg_noise_weight(min_dist_ratio: f64, N: u64, sec_param: usize) -> u64 {
    assert!(min_dist_ratio <= 0.5 && min_dist_ratio > 0.0);
    let d = (1.0 - 2.0 * min_dist_ratio).log2();
    let mut t = 40.max((-(sec_param as f64) / d) as u64);
    if N < 512 {
        t = t.max(64);
    }
    t.next_multiple_of(PARALLEL_TREES as u64)
}

fn conf(num_ots: u64) -> PprfConfig {
    // parameter for libOTe osuCrypto::MultType::ExConv7x24
    let scaler = 2;
    let num_partitions = get_reg_noise_weight(0.15, num_ots * scaler, 128);
    let size_per = 4.max(
        (num_ots * scaler)
            .div_ceil(num_partitions)
            .next_multiple_of(2),
    );
    PprfConfig::new(size_per as usize, num_partitions as usize)
}

fn get_cons_levels(
    tree: &mut [[Block; PARALLEL_TREES]],
    i: usize,
) -> (
    &mut [[Block; PARALLEL_TREES]],
    &mut [[Block; PARALLEL_TREES]],
) {
    let size0 = 1 << i;
    let offset0 = size0 - 1;
    let tree = &mut tree[offset0..];
    let (level0, rest) = tree.split_at_mut(size0);
    let size1 = 1 << (i + 1);
    debug_assert_eq!(size0 + offset0, size1 - 1);
    let level1 = &mut rest[..size1];
    (level0, level1)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
