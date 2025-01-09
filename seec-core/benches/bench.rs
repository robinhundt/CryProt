use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, RngCore};
use seec_core::transpose::transpose_bitmatrix_into;

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 128;
    let cols = 2_usize.pow(24) / 8;
    let mut out = vec![0; rows * cols];
    // 1_000_000 = cols * 8 (byte size)
    c.bench_function("transpose 128 x 2**24", |b| {
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
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
