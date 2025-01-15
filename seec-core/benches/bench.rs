use std::arch::x86_64::_mm256_setzero_si256;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, RngCore};
use seec_core::transpose::{avx2, portable};

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 128;
    let cols = 2_usize.pow(20) / 8;
    let mut out = vec![0; rows * cols];
    c.bench_function("portable (sse2) transpose 128 x 2**20", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; rows * cols];
                thread_rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| portable::transpose_bitmatrix(&bitmat, &mut out, rows),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("avx2 transpose 128 x 2**20", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; rows * cols];
                thread_rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| avx2::transpose_bitmatrix(&bitmat, &mut out, rows),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("avx2 transpose 128 x 128", |b| {
        b.iter_batched(
            || {
                let mut bitmat = [unsafe { _mm256_setzero_si256() }; 64];
                thread_rng().fill_bytes(&mut bytemuck::cast_slice_mut(&mut bitmat));
                bitmat
            },
            |mut bitmat| avx2::avx_transpose128x128(&mut bitmat),
            BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "tokio-rayon")]
fn bench_spawn_compute(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    c.bench_function("spawn_compute overhead", |b| {
        b.to_async(&rt).iter(|| async {
            let jh = seec_core::tokio_rayon::spawn_compute(|| 42);
            assert_eq!(42, jh.await);
        });
    });
}

#[cfg(not(feature = "tokio-rayon"))]
criterion_group!(benches, criterion_benchmark);

#[cfg(feature = "tokio-rayon")]
criterion_group!(benches, criterion_benchmark, bench_spawn_compute);

criterion_main!(benches);
