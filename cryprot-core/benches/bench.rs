use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use cryprot_core::{
    Block,
    aes_hash::FIXED_KEY_HASH,
    aes_rng::AesRng,
    buf::Buf,
    transpose::{avx2, portable},
};
use rand::{RngCore, rng};

fn criterion_benchmark(c: &mut Criterion) {
    let rows = 128;
    let cols = 2_usize.pow(20) / 8;
    let mut out = vec![0; rows * cols];
    c.bench_function("portable (sse2) transpose 128 x 2**20", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; rows * cols];
                rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| portable::transpose_bitmatrix(&bitmat, &mut out, rows),
            BatchSize::SmallInput,
        )
    });

    #[cfg(target_feature = "avx2")]
    c.bench_function("avx2 transpose 128 x 2**20", |b| {
        b.iter_batched(
            || {
                let mut bitmat = vec![0; rows * cols];
                rng().fill_bytes(&mut bitmat);
                bitmat
            },
            |bitmat| unsafe { avx2::transpose_bitmatrix(&bitmat, &mut out, rows) },
            BatchSize::SmallInput,
        )
    });

    #[cfg(target_feature = "avx2")]
    c.bench_function("avx2 transpose 128 x 128", |b| {
        b.iter_batched(
            || {
                let mut bitmat = [unsafe { std::arch::x86_64::_mm256_setzero_si256() }; 64];
                rng().fill_bytes(&mut bytemuck::cast_slice_mut(&mut bitmat));
                bitmat
            },
            |mut bitmat| unsafe { avx2::avx_transpose128x128(&mut bitmat) },
            BatchSize::SmallInput,
        )
    });

    let mut buf = Vec::zeroed(4 * 1024_usize.pow(2));
    c.bench_function("cr_hash_slice_mut", |b| {
        b.iter(|| {
            FIXED_KEY_HASH.cr_hash_slice_mut(&mut buf);
        });
    });

    let mut buf = Vec::zeroed(4 * 1024_usize.pow(2));
    c.bench_function("tmmo_hash_slice_mut", |b| {
        b.iter(|| {
            FIXED_KEY_HASH.tccr_hash_slice_mut(&mut buf, |i| Block::from(i));
        });
    });

    let mut buf = Vec::zeroed(100 * 1024_usize.pow(2));
    let mut rng = AesRng::new();
    c.bench_function("aes rng fill_bytes", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut buf);
        });
    });
}

#[cfg(feature = "tokio-rayon")]
fn bench_spawn_compute(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    c.bench_function("spawn_compute overhead", |b| {
        b.to_async(&rt).iter(|| async {
            let jh = cryprot_core::tokio_rayon::spawn_compute(|| 42);
            assert_eq!(42, jh.await.unwrap());
        });
    });
}

#[cfg(not(feature = "tokio-rayon"))]
criterion_group!(benches, criterion_benchmark);

#[cfg(feature = "tokio-rayon")]
criterion_group!(benches, criterion_benchmark, bench_spawn_compute);

criterion_main!(benches);
