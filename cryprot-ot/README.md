# CryProt-OT

> [!CAUTION]  
> This is research software and not intended for production use cases.

Oblivious transfer implementations. Currently implemented are the following:

- base OT: "Simplest OT" [[CO15](https://eprint.iacr.org/2015/267)]
- semi-honest OT extension: optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)] protocol
- malicious OT extension: optimized [[KOS15]](https://eprint.iacr.org/2015/546.pdf) protocol
- silent OT extension: [[BCG+19](https://eprint.iacr.org/2019/1159)] silent OT using [[RRT23](https://eprint.iacr.org/2023/882)] code (semi-honest and malicious with [[YWL+20](https://dl.acm.org/doi/pdf/10.1145/3372297.3417276)] consistency check)

This library is heavily inspired by and in parts a port of the C++ [libOTe](https://github.com/osu-crypto/libOTe) library.

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

