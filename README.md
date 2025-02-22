# CryProt

> [!CAUTION]  
> This is research software and not intended for production use cases.

The `cryprot` crates implement several **cryp**tographic **prot**ocols and utilities for their implementation. The current focus is on obilvious transfer implementations.

| Crate | Description | crates.io | Docs |
|---|---|---|---|
| [`cryprot-core`] | Core utilities such as a 128-bit block. | [![crates.io](https://img.shields.io/crates/v/cryprot-core)](https://crates.io/crates/cryprot-core) | [![docs.rs](https://img.shields.io/docsrs/cryprot-core)](https://docs.rs/cryprot-core) |
| [`cryprot-net`] | Networking abstractions built atop [s2n-quic](https://docs.rs/s2n-quic/latest/s2n_quic/). | [![crates.io](https://img.shields.io/crates/v/cryprot-net)](https://crates.io/crates/cryprot-net) | [![docs.rs](https://img.shields.io/docsrs/cryprot-net)](https://docs.rs/cryprot-net) |
| [`cryprot-pprf`] | Distributed PPRF implementation used in Silent OT [[BCG+19]](https://eprint.iacr.org/2019/1159), based on [libOTe](https://github.com/osu-crypto/libOTe). | [![crates.io](https://img.shields.io/crates/v/cryprot-pprf)](https://crates.io/crates/cryprot-pprf) | [![docs.rs](https://img.shields.io/docsrs/cryprot-pprf)](https://docs.rs/cryprot-pprf) |
| [`cryprot-codes`] | Expand-convolute linear code [[RRT23]](https://eprint.iacr.org/2023/882), based on [libOTe](https://github.com/osu-crypto/libOTe), used in Silent OT. | [![crates.io](https://img.shields.io/crates/v/cryprot-codes)](https://crates.io/crates/cryprot-codes) | [![docs.rs](https://img.shields.io/docsrs/cryprot-codes)](https://docs.rs/cryprot-codes) |
| [`cryprot-ot`] | Oblivious transfer implementations:<br>• Base OT: "Simplest OT" [[CO15]](https://eprint.iacr.org/2015/267)<br>• OT extensions: [[IKNP03]](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)<br>• Malicious OT extension: [[KOS15]](https://eprint.iacr.org/2015/546.pdf)<br>• Silent OT extension: [[BCG+19]](https://eprint.iacr.org/2019/1159) Silent OT using [[RRT23]](https://eprint.iacr.org/2023/882) code and optional [[YWL+20]](https://dl.acm.org/doi/pdf/10.1145/3372297.3417276) consistency check for malicious security. | [![crates.io](https://img.shields.io/crates/v/cryprot-ot)](https://crates.io/crates/cryprot-ot) | [![docs.rs](https://img.shields.io/docsrs/cryprot-ot)](https://docs.rs/cryprot-ot) |


## Platform Support
All crates test-suites are run on Githubs `ubuntu-latest`, `windows-latest` and `macos-latest` (aarch64 ARM architecture) runners. Other platforms might work but are not tested.

## Performance
Performance is optimized for `x86_64` Linux systems with AVX2 instructions available and transparent huge table support. The protocols will work on the other supported platforms but might exhibit lower performance.  
To enable all target features your CPU offers, compile with `RUSTFLAGS="-C target-cpu=native"` environment variable set (not needed when cloning the repo, as it is specified in [`.cargo/config.toml`]).

## Benchmarks
We continously run the benchmark suite in CI witht the results publicly available on [bencher.dev](https://bencher.dev/perf/cryprot/plots). The raw criterion output, including throughput is available in the logs of the [bench workflow](https://github.com/robinhundt/CryProt/actions/workflows/bench.yml) (latest run > benchmarks job > Run Benchmarks step).

Benchmarks can be run locally using:
```
cargo bench
```
(Note that on a laptop, thermal throttling might lead to unreliable results.)

## OT Extension Benchmarks
Following are benchmark numbers for several OT protocols on a 4-core VM running on an AMD EPYC 9454P. For up to date benchmarks view the links in the benchmarks section. Each OT sender/receiver uses one worker thread and number of cores many background threads for communication (which by default is also encrypted as part of QUIC). 

| Benchmark                                         | Mean Throughput (million OT/s) |
|--------------------------------------------------|--------------------------|
| Semi-honest R-OT ext. (2^24 R-OTs)       | 51.539                   |
| Malicious R-OT ext. (2^24 R-OTs)         | 33.663                   |
| Semi-Honest Silent C-OT ext. (2^21 C-OTs)          | 4.2306                   |
| Semi-Honest Silent R-OT ext. (2^21 R-OTs)              | 9.5426                   |
| Malicious Silent R-OT ext. (2^21 R-OTs)    | 7.4180                   |

Silent OT will perform faster for smaller numbers of OTs at slightly increased communication.

Our OT implementations should be on par or faster than those in libOTe. In the future we want to benchmark libOTe on the same hardware for a fair comparison.

**Base OT Benchmark:**

| Benchmark      | Mean Time (ms) |
|---------------|---------------|
| 128 base R-OTs   | 28.001        |


## Unsafe usage
`unsafe` is used in `cryprot-codes` and `cryprot-core` for performance reasons, most importantly to use SIMD intrinsics. The test suite of those two crates is additionally run using [miri](https://github.com/rust-lang/miri) to check for undefined behavior.

## Constant time operations
We try to use constant time operations when operating secret data and make use of [subtle's](https://docs.rs/subtle/latest/subtle/) `Choice` type. However, we may have missed non-constant operations on sensitive data and subtle's `Choice` provides no guarantee for constant-timeness. We provide no guarantee regarding constant-time.

[`cryprot-core`]: ./cryprot-core
[`cryprot-net`]: ./cryprot-net
[`cryprot-pprf`]: ./cryprot-pprf
[`cryprot-codes`]: ./cryprot-codes
[`cryprot-ot`]: ./cryprot-ot

[`.cargo/config.toml`]: ./.cargo/config.toml 