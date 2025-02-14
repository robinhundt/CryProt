use bytemuck::cast_slice_mut;
use criterion::{criterion_group, criterion_main, Criterion};
use cryprot_codes::ex_conv::ExConvCode;
use cryprot_core::{buf::Buf, Block};
use rand::{thread_rng, RngCore};

fn criterion_benchmark(c: &mut Criterion) {
    {
        let mut g = c.benchmark_group("ex conv");

        let power = 18;
        let num_ots = 2_usize.pow(power);
        let code = ExConvCode::new(num_ots);
        let mut data: Vec<Block> = Vec::zeroed(code.conf().code_size);
        thread_rng().fill_bytes(cast_slice_mut(&mut data));
        g.bench_function(format!("dual_encode blocks msg_size=2**{power}"), |b| {
            b.iter(|| {
                code.dual_encode(&mut data);
            });
        });

        let power = 23;
        let num_ots = 2_usize.pow(power);
        let code = ExConvCode::new(num_ots);
        let mut data: Vec<Block> = Vec::zeroed(code.conf().code_size);
        thread_rng().fill_bytes(cast_slice_mut(&mut data));
        g.sample_size(10);
        g.bench_function(format!("dual_encode blocks msg_size=2**{power}"), |b| {
            b.iter(|| {
                code.dual_encode(&mut data);
            });
        });
    }

    #[cfg(feature = "bench-libote")]
    {
        use cryprot_codes::ex_conv::ExConvCodeConfig;

        let mut g = c.benchmark_group("ex conv libote");
        let default_conf = ExConvCodeConfig::default();

        let power = 18;
        let num_ots = 2_usize.pow(power);
        let mut data: Vec<Block> = Vec::zeroed(num_ots * 2);
        thread_rng().fill_bytes(cast_slice_mut(&mut data));
        let mut libote_code = libote_codes::ExConvCode::new(
            num_ots as u64,
            (num_ots * 2) as u64,
            default_conf.expander_weight as u64,
            default_conf.accumulator_size as u64,
        );
        g.bench_function(format!("dual_encode blocks msg_size=2**{power}"), |b| {
            b.iter(|| {
                libote_code.dual_encode_block(cast_slice_mut(&mut data));
            });
        });

        let power = 23;
        let num_ots = 2_usize.pow(power);
        let mut data: Vec<Block> = Vec::zeroed(num_ots * 2);
        thread_rng().fill_bytes(cast_slice_mut(&mut data));
        let mut libote_code = libote_codes::ExConvCode::new(
            num_ots as u64,
            (num_ots * 2) as u64,
            default_conf.expander_weight as u64,
            default_conf.accumulator_size as u64,
        );
        g.sample_size(10);
        g.bench_function(format!("dual_encode blocks msg_size=2**{power}"), |b| {
            b.iter(|| {
                libote_code.dual_encode_block(cast_slice_mut(&mut data));
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
