# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `from_var_bytes` to scalar [#126]

## [0.13.1] - 2023-10-11

### Changed

- Expose `EDWARDS_D` constant

## [0.13.0] - 2023-06-07

### Added

- Add more tests for wnaf computation [#104]

### Changed

- Merge upstream changes from `zkcrypto` [#115]

### Removed

- Remove `canonical` and `canonical_derive` dependency [#109]

## [0.12.1] - 2022-10-19

### Added

- Add support for `rkyv-impl` under `no_std`

## [0.12.0] - 2022-08-17

### Added

- Add `CheckBytes` implementations on `rkyv`ed structures
- Add `rkyv` implementations on structures [#95]

## Changed

- Update `dusk-bls12_381` to version `0.11`

## [0.11.1] - 2022-04-06

### Added

- Add const directive to JubJubExtended [#93]

## [0.10.1] - 2021-09-08

### Fixed

- Fix ZZIP-216 bug with neg identity encoding [#82]

## [0.10.0] - 2021-04-28

### Changed

- Update `dusk-bls12_381` to `0.8.0` [#73]
- Update `canonical` to `0.6.0` [#78]

## [0.9.0] - 2021-04-12

### Changed

- Set `blake2` as dev dependency [#64]

### Fixed

- Fix `no_std` compatibility [#67]

## [0.8.1] - 2021-02-09

### Changed

- Fix on `default-features` prop of `dusk-bls12_381` dependency [#61]

## [0.8.0] - 2021-01-27

### Changed

- Update `canonical` to `v0.5`

## [0.7.0] - 2021-01-14

### Added

- Add `Serializable` trait to all structures

### Changed

- Change return value of `from_bytes` from `Option` / `CtOption` into `Result<Self, Error>`

### Removed

- Remove manual implementation of `from_bytes` and `to_bytes` from all structures

## [0.6.0] - 2021-01-05

### Changed

- Update `dusk-bls12_381` to `0.4.0`
- Update `rand_core` to `0.6`

## [0.5.0] - 2020-11-09

### Changed

- Update `dusk-bls12_381` to `0.3.0`
- Export `Fr` as `JubJubScalar`
- Create `no-std` compatibility via feature
- Rename `AffinePoint` to `JubJubAffine`
- Rename `ExtendedPoint` to `JubJubExtended`

## [0.4.0] - 2020-11-03

### Changed

- Derive `Canon` for `ExtendedPoint`
- Add `canonical` dependencies behind feature flag

## [0.3.10] - 2020-11-02

### Changed

- Derive `Canon` for `Fr` and `AffinePoint`

## [0.3.9] - 2020-10-29

### Changed

- Update `dusk-bls12_381` to `0.1.5`

## [0.3.8] - 2020-09-11

### Changed

- Update to latest `subtle` & `dusk-bls12_381` versions

## [0.3.7] - 2020-08-19

### Added

- Add `ExtendedPoint::to_hash_inputs`

## [0.3.6] - 2020-08-13

### Added

- Use standard docs.rs documentation engine [#35]
- Add `no_std` as optional feature [#33]
- Add ElGamal encryption scheme [#32]
- Make generators available as extended points [#31]

## [0.3.5] - 2020-07-29

### Fixed

- Fix `JubJub::random` causing stack overflow [#25]

## [0.3.4] - 2020-07-28

### Fixed

- Fix `dhke` to return an elliptic curve point instead of scalar

## [0.3.3] - 2020-07-25

### Fixed

- Fix `GENERATOR_NUMS` value and add tests to check it's correct

## [0.3.2] - 2020-07-24

### Added

- Add `GENERATOR_NUMS` & export it

## [0.3.1] - 2020-07-17

### Added

- Export curve-generator
- Add getters for point coordinates in `AffinePoint` and `ExtendedPoint`
- Implement DHKE functionality
- Implement `random` for `Fr`
- Implement WNaf for `Fr`

### Removed

- Remove `no_std` compatibility.

## [0.3.0] - 2019-12-04

### Initial fork from [`zkcrypto/jubjub`]

[#126]: https://github.com/dusk-network/jubjub/issues/126
[#115]: https://github.com/dusk-network/jubjub/issues/115
[#109]: https://github.com/dusk-network/jubjub/issues/109
[#104]: https://github.com/dusk-network/jubjub/issues/104
[#95]: https://github.com/dusk-network/jubjub/issues/95
[#93]: https://github.com/dusk-network/jubjub/issues/93
[#82]: https://github.com/dusk-network/jubjub/issues/82
[#78]: https://github.com/dusk-network/jubjub/issues/78
[#73]: https://github.com/dusk-network/jubjub/issues/73
[#67]: https://github.com/dusk-network/jubjub/issues/67
[#64]: https://github.com/dusk-network/jubjub/issues/64
[#61]: https://github.com/dusk-network/jubjub/issues/61
[#35]: https://github.com/dusk-network/jubjub/issues/35
[#33]: https://github.com/dusk-network/jubjub/issues/33
[#32]: https://github.com/dusk-network/jubjub/issues/32
[#31]: https://github.com/dusk-network/jubjub/issues/31
[#25]: https://github.com/dusk-network/jubjub/issues/25

[Unreleased]: https://github.com/dusk-network/jubjub/compare/v0.13.1...HEAD
[0.13.1]: https://github.com/dusk-network/jubjub/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/dusk-network/jubjub/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/dusk-network/jubjub/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/dusk-network/jubjub/compare/v0.10.1...v0.12.0
[0.11.1]: https://github.com/dusk-network/jubjub/compare/v0.10.1...v0.11.1
[0.10.1]: https://github.com/dusk-network/jubjub/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/dusk-network/jubjub/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dusk-network/jubjub/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/dusk-network/jubjub/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dusk-network/jubjub/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/jubjub/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dusk-network/jubjub/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/dusk-network/jubjub/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/jubjub/compare/v0.3.10...v0.4.0
[0.3.10]: https://github.com/dusk-network/jubjub/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/dusk-network/jubjub/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/dusk-network/jubjub/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/dusk-network/jubjub/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/dusk-network/jubjub/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/dusk-network/jubjub/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/dusk-network/jubjub/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/dusk-network/jubjub/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/dusk-network/jubjub/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/dusk-network/jubjub/compare/0.3.0...v0.3.1
[0.3.0]: https://github.com/dusk-network/jubjub/releases/tag/0.3.0

[`zkcrypto/jubjub`]: https://github.com/zkcrypto/jubjub
