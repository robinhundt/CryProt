# CryProt

> [!CAUTION]  
> This is research software and not intended for production use cases.

The `cryprot` crates implement several **cryp**tographic **prot**ocols.

Crates:
- `cryprot-core`: Core utilities such as a 128-bit block.
- `cryprot-net`: Networking abstractions built atop [s2n-quic](https://docs.rs/s2n-quic/latest/s2n_quic/).
- `cryprot-pprf`: distributed PPRF implementation used in the Silent OT protocol [[BCG+19](https://eprint.iacr.org/2019/1159)] (based on [libOTe](https://github.com/osu-crypto/libOTe))
- `cryprot-codes`: implementation of expand-convolute linear code [[RRT23](https://eprint.iacr.org/2023/882)] (based on [libOTe](https://github.com/osu-crypto/libOTe)) used in Silent OT
- `cryprot-ot`: Oblivious transfer implementations
    - base OT: "Simplest OT" [[CO15](https://eprint.iacr.org/2015/267)]
    - classic OT extensions: optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)] protocol
    - malicious OT extension: optimized [[KOS15]](https://eprint.iacr.org/2015/546.pdf) protocol
    - silent OT extension: [[BCG+19](https://eprint.iacr.org/2019/1159)] silent OT using [[RRT23](https://eprint.iacr.org/2023/882)] code and optional [[YWL+20]](https://dl.acm.org/doi/pdf/10.1145/3372297.3417276) consistency check for malicious security

