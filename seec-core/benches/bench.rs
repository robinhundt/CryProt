use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, RngCore};
use seec_core::transpose::transpose_bitmatrix;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("transpose 128 x 1_000_000", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; 128 * 125_000];
                thread_rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| transpose_bitmatrix(&bitmat, 128),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
