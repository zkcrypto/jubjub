# Unreleased

### Change
- Update `dusk-bls12_381` to `0.8.0-rc.0`.

# 0.9.0
### Fix
- Fix no_std compatibility for crate.[#67](https://github.com/dusk-network/jubjub/pull/67)

### Change
- Set `blake2` as dev-dep. [#64](https://github.com/dusk-network/jubjub/issues/64)

# 0.8.1
### Change
- Fix on default-features prop of dusk-bls12_381 dependency [#61](https://github.com/dusk-network/jubjub/issues/61)

# 0.8.0
### Change
- Update canonical to `v0.5`

# 0.7.0
### Add
- Add `Serializable` trait to all structures

### Remove
- Remove manual implementation of `from_bytes` and `to_bytes` from all structures

### Change
- Change return value of `from_bytes` from  `Option` / `CtOption` into `Result<Self, Error>`

# 0.6.0
### Change
- Update `dusk-bls12_381` to `0.4.0`.
- Update `rand_core` to `0.6`.

# 0.5.0
### Change
- Update `dusk-bls12_381` to `0.3.0`.
- Export `Fr` as `JubJubScalar`
- Create no-std compatibility via feature.
- Rename `AffinePoint` to `JubJubAffine`
- Rename `ExtendedPoint` to `JubJubExtended`

# 0.4.0
### Change
- Derive `Canon` for `ExtendedPoint`.
- Add `canonical` deps as optional behind a feature flag.

# 0.3.10
### Change
- Derive `Canon` for `Fr` & `AffinePoint`.

# 0.3.9
### Change
- Update dusk-bls12_381 to 0.1.5.

# 0.3.8
### Change
- Use latest subtle & bls12_381 versions.

# 0.3.6
### Add
- Implements #25 Use standard docs.rs documentation engine.
- Implements #31 Generators available as extended points.
- Implements #32 ElGamal encryption scheme.
- Implements #33 no_std as optional feature

# 0.3.5
### Fix
- Issue #25 JubJub random function causes stack overflow.

# 0.3.4
### Fix
- Fix `dhke` to return an elliptic curve point instead of scalar.

# 0.3.3
### Fix
- Fix `GENERATOR_NUMS` value and add tests to check it's correct.

# 0.3.2 [yanked]
### Add
- Add `GENERATOR_NUMS` & export it.

# 0.3.1
### Add
- Export curve-generator.
- Add getters for point coordinates in AffinePoint and ExtendedPoint.
- Implement DHKE functionality.
- Implement random for Fr.
- Implement WNaf for Fr

### Remove
* Remove the #[no_std] compatibility.

# 0.3.0

This release now depends on the `bls12_381` crate, which exposes the `Fq` field type that we re-export.

* The `Fq` and `Fr` field types now have better constant function support for various operations and constructors.
* We no longer depend on the `byteorder` crate.
* We've bumped our `rand_core` dev-dependency up to 0.5.
* We've removed the `std` and `nightly` features.
* We've bumped our dependency of `subtle` up to `^2.2.1`.

# 0.2.0

This release switches to `subtle 2.1` to bring in the `CtOption` type, and also makes a few useful API changes.

* Implemented `Mul<Fr>` for `AffineNielsPoint` and `ExtendedNielsPoint`
* Changed `AffinePoint::to_niels()` to be a `const` function so that constant curve points can be constructed without statics.
* Implemented `multiply_bits` for `AffineNielsPoint`, `ExtendedNielsPoint`
* Removed `CtOption` and replaced it with `CtOption` from `subtle` crate.
* Modified receivers of some methods to reduce stack usage
* Changed various `into_bytes` methods into `to_bytes`

# 0.1.0

Initial release.
