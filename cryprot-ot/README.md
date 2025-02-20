# CryProt-OT

> [!CAUTION]  
> This is research software and not intended for production use cases.

Oblivious transfer implementations. Currently implemented are the following:

- base OT: "Simplest OT" [[CO15](https://eprint.iacr.org/2015/267)]
- semi-honest OT extension: optimized [[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)] protocol
- malicious OT extension: optimized [[KOS15]](https://eprint.iacr.org/2015/546.pdf) protocol
- silent OT extension: [[BCG+19](https://eprint.iacr.org/2019/1159)] silent OT using [[RRT23](https://eprint.iacr.org/2023/882)] code (semi-honest and malicious with [[YWL+20]](https://dl.acm.org/doi/pdf/10.1145/3372297.3417276) consistency check)

This library is heavily inspired by and in parts a port of the C++ [libOTe](https://github.com/osu-crypto/libOTe) library.
