use std::arch::x86_64::_mm256_setzero_si256;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, RngCore};
use seec_core::transpose::{avx2::avx_transpose128x128, transpose_bitmatrix_into};

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 128;
    let cols = 2_usize.pow(20) / 8;
    let mut out = vec![0; rows * cols];
    // 1_000_000 = cols * 8 (byte size)
    c.bench_function("transpose 128 x 2**20", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; rows * cols];
                thread_rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| transpose_bitmatrix_into(&bitmat, &mut out, rows),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("avx transpose 128 x 128", |b| {
        b.iter_batched(
            || {
                let mut bitmat = [unsafe { _mm256_setzero_si256() }; 64];
                thread_rng().fill_bytes(&mut bytemuck::cast_slice_mut(&mut bitmat));
                bitmat
            },
            |mut bitmat| avx_transpose128x128(&mut bitmat),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
