use bytemuck::cast_slice_mut;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, RngCore};
use seec_codes::ex_conv::ExConvCode;
use seec_core::{buf::Buf, Block};

fn criterion_benchmark(c: &mut Criterion) {
    let num_ots = 2_usize.pow(18);
    let code = ExConvCode::new(num_ots);

    let mut data: Vec<Block> = Vec::zeroed(code.conf().code_size);
    thread_rng().fill_bytes(cast_slice_mut(&mut data));
    let mut g = c.benchmark_group("ex conv");
    g.bench_function("dual_encode blocks", |b| {
        b.iter(|| {
            code.dual_encode(&mut data);
        });
    });
    drop(g);

    let mut g = c.benchmark_group("ex conv libote");
    let mut libote_code = libote::ExConvCode::new(
        num_ots as u64,
        code.conf().code_size as u64,
        code.conf().expander_weight as u64,
        code.conf().accumulator_size as u64,
    );
    g.bench_function("dual_encode blocks", |b| {
        b.iter(|| {
            libote_code.dual_encode_block(cast_slice_mut(&mut data));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
