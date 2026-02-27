# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/robinhundt/CryProt/compare/cryprot-core-v0.3.0...cryprot-core-v0.3.1) - 2026-02-27

### Added

- *(aes)* update aes dependency and PAR_BLOCKS const

### Other

- *(deps)* bump proptest from 1.9.0 to 1.10.0
- *(rand)* update rand and rand_core to 0.10
- *(bench)* use std black_box

## [0.3.0](https://github.com/robinhundt/CryProt/compare/cryprot-core-v0.2.0...cryprot-core-v0.3.0) - 2026-01-21

### Removed
- [**breaking**] remove `nightly` feature ([#30](https://github.com/robinhundt/CryProt/pull/30))

### Changed
- set is_nightly cfg in build.rs if using nightly compiler ([#30](https://github.com/robinhundt/CryProt/pull/30))
- refactor AVX2 transpose for better understandability and less use of unsafe ([#13](https://github.com/robinhundt/CryProt/pull/13))
- remove unsafe from portable transpose implementation ([#14](https://github.com/robinhundt/CryProt/pull/14))


### Other
- update dependencies
