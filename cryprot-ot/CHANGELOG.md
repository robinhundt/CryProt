# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/robinhundt/CryProt/compare/cryprot-ot-v0.2.2...cryprot-ot-v0.3.0) - 2026-04-05

### Breaking
- Previous `cryprot_ot::base` is moved to `cryprot_ot::simplest_ot`

### Added
- add ML-KEM as an option for base OT ([#48](https://github.com/robinhundt/CryProt/pull/48) by @dartdart26)
- added type aliases `BaseOt` and `BaseOtError` in `cryprot_ot` that point to Simplest OT or ML-KEM base OT
    implementation, depending on if one of the `ml-kem-base-ot-<k>` features is enabled ([#48](https://github.com/robinhundt/CryProt/pull/48))

## [0.2.2](https://github.com/robinhundt/CryProt/compare/cryprot-ot-v0.2.1...cryprot-ot-v0.2.2) - 2026-03-05

### Other

- *(rand)* update rand and rand_core to 0.10
- *(docs)* clarify base OT message security

## [0.2.1](https://github.com/robinhundt/CryProt/compare/cryprot-ot-v0.2.0...cryprot-ot-v0.2.1) - 2026-01-21

### Security

- fix silent OT malicious security ([#23](https://github.com/robinhundt/CryProt/pull/23))
