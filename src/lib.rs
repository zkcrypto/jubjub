//! This crate provides an implementation of the **Jubjub** elliptic curve and
//! its associated field arithmetic.
//! See [`README.md`](https://github.com/zkcrypto/jubjub/blob/master/README.md)
// for more details about Jubjub.
//!
//! # API
//!
//! * `JubJubAffine` / `JubJubExtended` which are implementations of Jubjub
//!   group arithmetic
//! * `AffineNielsPoint` / `ExtendedNielsPoint` which are pre-processed Jubjub
//!   points
//! * `BlsScalar`, which is the base field of Jubjub
//! * `Fr`, which is the scalar field of Jubjub
//! * `batch_normalize` for converting many `JubJubExtended`s into
//!   `JubJubAffine`s efficiently.
//!
//! # Constant Time
//!
//! All operations are constant time unless explicitly noted; these functions
//! will contain "vartime" in their name and they will be documented as variable
//! time.
//!
//! This crate uses the `subtle` crate to perform constant-time operations.

#![cfg_attr(not(feature = "std"), no_std)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
// This lint is described at
// https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_arithmetic_impl
// In our library, some of the arithmetic will necessarily involve various
// binary operators, and so this lint is triggered unnecessarily.
#![allow(clippy::suspicious_arithmetic_impl)]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(feature = "canon")]
use canonical_derive::Canon;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use dusk_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[macro_use]
mod util;
mod fr;

/// Implementation of ElGamal encryption scheme with JubJub
pub mod elgamal;

pub use dusk_bls12_381::BlsScalar;
pub use fr::Fr as JubJubScalar;

pub(crate) use fr::Fr;

/// A better name than Fr.
pub type Scalar = Fr;

const FR_MODULUS_BYTES: [u8; 32] = [
    183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166,
    0, 59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
];

/// This represents a Jubjub point in the affine `(x, y)`
/// coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct JubJubAffine {
    x: BlsScalar,
    y: BlsScalar,
}

impl Neg for JubJubAffine {
    type Output = JubJubAffine;

    /// This computes the negation of a point `P = (x, y)`
    /// as `-P = (-x, y)`.
    #[inline]
    fn neg(self) -> JubJubAffine {
        JubJubAffine {
            x: -self.x,
            y: self.y,
        }
    }
}

impl ConstantTimeEq for JubJubAffine {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl PartialEq for JubJubAffine {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for JubJubAffine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        JubJubAffine {
            x: BlsScalar::conditional_select(&a.x, &b.x, choice),
            y: BlsScalar::conditional_select(&a.y, &b.y, choice),
        }
    }
}

/// Use a fixed generator point.
/// The point is then reduced according to the prime field. We need only to
/// state the coordinates, so users can exploit its properties
/// which are proven by tests, checking:
/// - It lies on the curve,
/// - Is of prime order,
/// - Is not the identity point.
/// Using:
///     x = 0x3fd2814c43ac65a6f1fbf02d0fd6cce62e3ebb21fd6c54ed4df7b7ffec7beaca
//      y = 0x0000000000000000000000000000000000000000000000000000000000000012
pub const GENERATOR: JubJubAffine = JubJubAffine {
    x: BlsScalar::from_raw([
        0x4df7b7ffec7beaca,
        0x2e3ebb21fd6c54ed,
        0xf1fbf02d0fd6cce6,
        0x3fd2814c43ac65a6,
    ]),
    y: BlsScalar::from_raw([
        0x0000000000000012,
        000000000000000000,
        000000000000000000,
        000000000000,
    ]),
};

/// [`GENERATOR`] in [`JubJubExtended`] form
pub const GENERATOR_EXTENDED: JubJubExtended = JubJubExtended {
    x: GENERATOR.x,
    y: GENERATOR.y,
    z: BlsScalar::one(),
    t1: GENERATOR.x,
    t2: GENERATOR.y,
};

/// GENERATOR NUMS which is obtained following the specs in:
/// https://app.gitbook.com/@dusk-network/s/specs/specifications/poseidon/pedersen-commitment-scheme
/// The counter = 18 and the hash function used to compute it was blake2b
/// Using:
///     x = 0x5e67b8f316f414f7bd9514c773fd4456931e316a39fe4541921710179df76377
//      y = 0x43d80eb3b2f3eb1b7b162dbeeb3b34fd9949ba0f82a5507a6705b707162e3ef8
pub const GENERATOR_NUMS: JubJubAffine = JubJubAffine {
    x: BlsScalar::from_raw([
        0x921710179df76377,
        0x931e316a39fe4541,
        0xbd9514c773fd4456,
        0x5e67b8f316f414f7,
    ]),
    y: BlsScalar::from_raw([
        0x6705b707162e3ef8,
        0x9949ba0f82a5507a,
        0x7b162dbeeb3b34fd,
        0x43d80eb3b2f3eb1b,
    ]),
};

/// [`GENERATOR_NUMS`] in [`JubJubExtended`] form
pub const GENERATOR_NUMS_EXTENDED: JubJubExtended = JubJubExtended {
    x: GENERATOR_NUMS.x,
    y: GENERATOR_NUMS.y,
    z: BlsScalar::one(),
    t1: GENERATOR_NUMS.x,
    t2: GENERATOR_NUMS.y,
};

// 202, 234, 123, 236, 255, 183, 247, 77, 237, 84, 108, 253, 33, 187, 62, 46,
// 230, 204, 214,15, 45, 240, 251, 241, 166, 101, 172, 67, 76, 129, 210, 63,

// 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0, 0, 0, 0, 0, 0, 0,

/// This represents an extended point `(X, Y, Z, T1, T2)`
/// with `Z` nonzero, corresponding to the affine point
/// `(X/Z, Y/Z)`. We always have `T1 * T2 = XY/Z`.
///
/// You can do the following things with a point in this
/// form:
///
/// * Convert it into a point in the affine form.
/// * Add it to an `JubJubExtended`, `AffineNielsPoint` or `ExtendedNielsPoint`.
/// * Double it using `double()`.
/// * Compare it with another extended point using `PartialEq` or `ct_eq()`.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct JubJubExtended {
    x: BlsScalar,
    y: BlsScalar,
    z: BlsScalar,
    t1: BlsScalar,
    t2: BlsScalar,
}

impl ConstantTimeEq for JubJubExtended {
    fn ct_eq(&self, other: &Self) -> Choice {
        // (x/z, y/z) = (x'/z', y'/z') is implied by
        //      (xz'z = x'z'z) and
        //      (yz'z = y'z'z)
        // as z and z' are always nonzero.

        (&self.x * &other.z).ct_eq(&(&other.x * &self.z))
            & (&self.y * &other.z).ct_eq(&(&other.y * &self.z))
    }
}

impl ConditionallySelectable for JubJubExtended {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        JubJubExtended {
            x: BlsScalar::conditional_select(&a.x, &b.x, choice),
            y: BlsScalar::conditional_select(&a.y, &b.y, choice),
            z: BlsScalar::conditional_select(&a.z, &b.z, choice),
            t1: BlsScalar::conditional_select(&a.t1, &b.t1, choice),
            t2: BlsScalar::conditional_select(&a.t2, &b.t2, choice),
        }
    }
}

impl PartialEq for JubJubExtended {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl Neg for JubJubExtended {
    type Output = JubJubExtended;

    /// Computes the negation of a point `P = (X, Y, Z, T)`
    /// as `-P = (-X, Y, Z, -T1, T2)`. The choice of `T1`
    /// is made without loss of generality.
    #[inline]
    fn neg(self) -> JubJubExtended {
        JubJubExtended {
            x: -self.x,
            y: self.y,
            z: self.z,
            t1: -self.t1,
            t2: self.t2,
        }
    }
}

impl From<JubJubAffine> for JubJubExtended {
    /// Constructs an extended point (with `Z = 1`) from
    /// an affine point using the map `(x, y) => (x, y, 1, x, y)`.
    fn from(affine: JubJubAffine) -> JubJubExtended {
        JubJubExtended {
            x: affine.x,
            y: affine.y,
            z: BlsScalar::one(),
            t1: affine.x,
            t2: affine.y,
        }
    }
}

impl<'a> From<&'a JubJubExtended> for JubJubAffine {
    /// Constructs an affine point from an extended point
    /// using the map `(X, Y, Z, T1, T2) => (XZ, Y/Z)`
    /// as Z is always nonzero. **This requires a field inversion
    /// and so it is recommended to perform these in a batch
    /// using [`batch_normalize`](crate::batch_normalize) instead.**
    fn from(extended: &'a JubJubExtended) -> JubJubAffine {
        // Z coordinate is always nonzero, so this is
        // its inverse.
        let zinv = extended.z.invert().unwrap();

        JubJubAffine {
            x: extended.x * &zinv,
            y: extended.y * &zinv,
        }
    }
}

impl From<JubJubExtended> for JubJubAffine {
    fn from(extended: JubJubExtended) -> JubJubAffine {
        JubJubAffine::from(&extended)
    }
}

/// This is a pre-processed version of an affine point `(x, y)`
/// in the form `(y + x, y - x, x * y * 2d)`. This can be added to an
/// [`JubJubExtended`](crate::JubJubExtended).
#[derive(Clone, Copy, Debug)]
pub struct AffineNielsPoint {
    y_plus_x: BlsScalar,
    y_minus_x: BlsScalar,
    t2d: BlsScalar,
}

impl AffineNielsPoint {
    /// Constructs this point from the neutral element `(0, 1)`.
    pub const fn identity() -> Self {
        AffineNielsPoint {
            y_plus_x: BlsScalar::one(),
            y_minus_x: BlsScalar::one(),
            t2d: BlsScalar::zero(),
        }
    }

    #[inline]
    fn multiply(&self, by: &[u8; 32]) -> JubJubExtended {
        let zero = AffineNielsPoint::identity();

        let mut acc = JubJubExtended::identity();

        // This is a simple double-and-add implementation of point
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading four bits because they're always
        // unset for Fr.
        for bit in by
            .iter()
            .rev()
            .flat_map(|byte| {
                (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8))
            })
            .skip(4)
        {
            acc = acc.double();
            acc += AffineNielsPoint::conditional_select(&zero, &self, bit);
        }

        acc
    }

    /// Multiplies this point by the specific little-endian bit pattern in the
    /// given byte array, ignoring the highest four bits.
    pub fn multiply_bits(&self, by: &[u8; 32]) -> JubJubExtended {
        self.multiply(by)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a AffineNielsPoint {
    type Output = JubJubExtended;

    fn mul(self, other: &'b Fr) -> JubJubExtended {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative_mixed!(AffineNielsPoint, Fr, JubJubExtended);

impl ConditionallySelectable for AffineNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffineNielsPoint {
            y_plus_x: BlsScalar::conditional_select(
                &a.y_plus_x,
                &b.y_plus_x,
                choice,
            ),
            y_minus_x: BlsScalar::conditional_select(
                &a.y_minus_x,
                &b.y_minus_x,
                choice,
            ),
            t2d: BlsScalar::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

/// This is a pre-processed version of an extended point `(X, Y, Z, T1, T2)`
/// in the form `(Y + X, Y - X, Z, T1 * T2 * 2d)`.
#[derive(Clone, Copy, Debug)]
pub struct ExtendedNielsPoint {
    y_plus_x: BlsScalar,
    y_minus_x: BlsScalar,
    z: BlsScalar,
    t2d: BlsScalar,
}

impl ConditionallySelectable for ExtendedNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedNielsPoint {
            y_plus_x: BlsScalar::conditional_select(
                &a.y_plus_x,
                &b.y_plus_x,
                choice,
            ),
            y_minus_x: BlsScalar::conditional_select(
                &a.y_minus_x,
                &b.y_minus_x,
                choice,
            ),
            z: BlsScalar::conditional_select(&a.z, &b.z, choice),
            t2d: BlsScalar::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

impl ExtendedNielsPoint {
    /// Constructs this point from the neutral element `(0, 1)`.
    pub const fn identity() -> Self {
        ExtendedNielsPoint {
            y_plus_x: BlsScalar::one(),
            y_minus_x: BlsScalar::one(),
            z: BlsScalar::one(),
            t2d: BlsScalar::zero(),
        }
    }

    #[inline]
    fn multiply(&self, by: &[u8; 32]) -> JubJubExtended {
        let zero = ExtendedNielsPoint::identity();

        let mut acc = JubJubExtended::identity();

        // This is a simple double-and-add implementation of point
        // multiplication, moving from most significant to least
        // significant bit of the scalar.
        //
        // We skip the leading four bits because they're always
        // unset for Fr.
        for bit in by
            .iter()
            .rev()
            .flat_map(|byte| {
                (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8))
            })
            .skip(4)
        {
            acc = acc.double();
            acc += ExtendedNielsPoint::conditional_select(&zero, &self, bit);
        }

        acc
    }

    /// Multiplies this point by the specific little-endian bit pattern in the
    /// given byte array, ignoring the highest four bits.
    pub fn multiply_bits(&self, by: &[u8; 32]) -> JubJubExtended {
        self.multiply(by)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a ExtendedNielsPoint {
    type Output = JubJubExtended;

    fn mul(self, other: &'b Fr) -> JubJubExtended {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative_mixed!(ExtendedNielsPoint, Fr, JubJubExtended);

/// `d = -(10240/10241)`
pub const EDWARDS_D: BlsScalar = BlsScalar::from_raw([
    0x01065fd6d6343eb1,
    0x292d7f6d37579d26,
    0xf5fd9207e6bd7fd4,
    0x2a9318e74bfa2b48,
]);

/// `2*EDWARDS_D`
pub const EDWARDS_D2: BlsScalar = BlsScalar::from_raw([
    0x020cbfadac687d62,
    0x525afeda6eaf3a4c,
    0xebfb240fcd7affa8,
    0x552631ce97f45691,
]);

impl Serializable<32> for JubJubAffine {
    type Error = BytesError;

    /// Converts this element into its byte representation.
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut tmp = self.y.to_bytes();
        let x = self.x.to_bytes();

        // Encode the sign of the x-coordinate in the most
        // significant bit.
        tmp[31] |= x[0] << 7;

        tmp
    }

    /// Attempts to interpret a byte representation of an
    /// affine point, failing if the element is not on
    /// the curve or non-canonical.
    fn from_bytes(b: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut b = b.clone();

        // Grab the sign bit from the representation
        let sign = b[31] >> 7;

        // Mask away the sign bit
        b[31] &= 0b0111_1111;

        // Interpret what remains as the y-coordinate
        let y = BlsScalar::from_bytes(&b)?;

        // -x^2 + y^2 = 1 + d.x^2.y^2
        // -x^2 = 1 + d.x^2.y^2 - y^2    (rearrange)
        // -x^2 - d.x^2.y^2 = 1 - y^2    (rearrange)
        // x^2 + d.x^2.y^2 = y^2 - 1     (flip signs)
        // x^2 (1 + d.y^2) = y^2 - 1     (factor)
        // x^2 = (y^2 - 1) / (1 + d.y^2) (isolate x^2)
        // We know that (1 + d.y^2) is nonzero for all y:
        //   (1 + d.y^2) = 0
        //   d.y^2 = -1
        //   y^2 = -(1 / d)   No solutions, as -(1 / d) is not a square

        let y2 = y.square();

        Option::from(
            ((y2 - BlsScalar::one())
                * ((BlsScalar::one() + EDWARDS_D * &y2)
                    .invert()
                    .unwrap_or(BlsScalar::zero())))
            .sqrt()
            .and_then(|x| {
                // Fix the sign of `x` if necessary
                let flip_sign = Choice::from((x.to_bytes()[0] ^ sign) & 1);
                let x_negated = -x;
                let final_x =
                    BlsScalar::conditional_select(&x, &x_negated, flip_sign);

                CtOption::new(JubJubAffine { x: final_x, y }, Choice::from(1u8))
            }),
        )
        .ok_or(BytesError::InvalidData)
    }
}

impl JubJubAffine {
    /// Constructs the neutral element `(0, 1)`.
    pub const fn identity() -> Self {
        JubJubAffine {
            x: BlsScalar::zero(),
            y: BlsScalar::one(),
        }
    }

    /// Multiplies this point by the cofactor, producing an
    /// `JubJubExtended`
    pub fn mul_by_cofactor(&self) -> JubJubExtended {
        JubJubExtended::from(*self).mul_by_cofactor()
    }

    /// Determines if this point is of small order.
    pub fn is_small_order(&self) -> Choice {
        JubJubExtended::from(*self).is_small_order()
    }

    /// Determines if this point is torsion free and so is
    /// in the prime order subgroup.
    pub fn is_torsion_free(&self) -> Choice {
        JubJubExtended::from(*self).is_torsion_free()
    }

    /// Determines if this point is prime order, or in other words that
    /// the smallest scalar multiplied by this point that produces the
    /// identity is `r`. This is equivalent to checking that the point
    /// is both torsion free and not the identity.
    pub fn is_prime_order(&self) -> Choice {
        let extended = JubJubExtended::from(*self);
        extended.is_torsion_free() & (!extended.is_identity())
    }

    /// Returns the `x`-coordinate of this point.
    pub fn get_x(&self) -> BlsScalar {
        self.x
    }

    /// Returns the `y`-coordinate of this point.
    pub fn get_y(&self) -> BlsScalar {
        self.y
    }

    /// Performs a pre-processing step that produces an `AffineNielsPoint`
    /// for use in multiple additions.
    pub const fn to_niels(&self) -> AffineNielsPoint {
        AffineNielsPoint {
            y_plus_x: BlsScalar::add(&self.y, &self.x),
            y_minus_x: BlsScalar::sub(&self.y, &self.x),
            t2d: BlsScalar::mul(&BlsScalar::mul(&self.x, &self.y), &EDWARDS_D2),
        }
    }

    /// Constructs an JubJubAffine given `x` and `y` without checking
    /// that the point is on the curve.
    pub const fn from_raw_unchecked(
        x: BlsScalar,
        y: BlsScalar,
    ) -> JubJubAffine {
        JubJubAffine { x, y }
    }

    /// This is only for debugging purposes and not
    /// exposed in the public API. Checks that this
    /// point is on the curve.
    #[cfg(test)]
    fn is_on_curve_vartime(&self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();

        &y2 - &x2 == BlsScalar::one() + &EDWARDS_D * &x2 * &y2
    }
}

impl JubJubExtended {
    /// Returns the `x`-coordinate of this point.
    pub fn get_x(&self) -> BlsScalar {
        self.x
    }

    /// Returns the `y`-coordinate of this point.
    pub fn get_y(&self) -> BlsScalar {
        self.y
    }

    /// Returns the `z`-coordinate of this point.
    pub fn get_z(&self) -> BlsScalar {
        self.z
    }

    /// Returns the `t1`-coordinate of this point.
    pub fn get_t1(&self) -> BlsScalar {
        self.t1
    }

    /// Returns the `t2`-coordinate of this point.
    pub fn get_t2(&self) -> BlsScalar {
        self.t2
    }

    /// Constructs an extended point from the neutral element `(0, 1)`.
    pub const fn identity() -> Self {
        JubJubExtended {
            x: BlsScalar::zero(),
            y: BlsScalar::one(),
            z: BlsScalar::one(),
            t1: BlsScalar::zero(),
            t2: BlsScalar::zero(),
        }
    }

    /// Determines if this point is the identity.
    pub fn is_identity(&self) -> Choice {
        // If this point is the identity, then
        //     x = 0 * z = 0
        // and y = 1 * z = z
        self.x.ct_eq(&BlsScalar::zero()) & self.y.ct_eq(&self.z)
    }

    /// Determines if this point is of small order.
    pub fn is_small_order(&self) -> Choice {
        // We only need to perform two doublings, since the 2-torsion
        // points are (0, 1) and (0, -1), and so we only need to check
        // that the x-coordinate of the result is zero to see if the
        // point is small order.
        self.double().double().x.ct_eq(&BlsScalar::zero())
    }

    /// Determines if this point is torsion free and so is contained
    /// in the prime order subgroup.
    pub fn is_torsion_free(&self) -> Choice {
        self.multiply(&FR_MODULUS_BYTES).is_identity()
    }

    /// Determines if this point is prime order, or in other words that
    /// the smallest scalar multiplied by this point that produces the
    /// identity is `r`. This is equivalent to checking that the point
    /// is both torsion free and not the identity.
    pub fn is_prime_order(&self) -> Choice {
        self.is_torsion_free() & (!self.is_identity())
    }

    /// Multiplies this element by the cofactor `8`.
    pub fn mul_by_cofactor(&self) -> JubJubExtended {
        self.double().double().double()
    }

    /// Performs a pre-processing step that produces an `ExtendedNielsPoint`
    /// for use in multiple additions.
    pub fn to_niels(&self) -> ExtendedNielsPoint {
        ExtendedNielsPoint {
            y_plus_x: &self.y + &self.x,
            y_minus_x: &self.y - &self.x,
            z: self.z,
            t2d: &self.t1 * &self.t2 * EDWARDS_D2,
        }
    }

    /// Returns two scalars suitable for hashing that represent the
    /// Extended Point.
    pub fn to_hash_inputs(&self) -> [BlsScalar; 2] {
        // The same JubJubAffine can have different JubJubExtended
        // representations, therefore we convert from Extended to Affine
        // before hashing, to ensure deterministic result
        let p = JubJubAffine::from(self);
        [p.x, p.y]
    }

    /// Computes the doubling of a point more efficiently than a point can
    /// be added to itself.
    pub fn double(&self) -> JubJubExtended {
        // Doubling is more efficient (three multiplications, four squarings)
        // when we work within the projective coordinate space (U:Z, V:Z). We
        // rely on the most efficient formula, "dbl-2008-bbjlp", as described
        // in Section 6 of "Twisted Edwards Curves" by Bernstein et al.
        //
        // See <https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp>
        // for more information.
        //
        // We differ from the literature in that we use (x, y) rather than
        // (x, y) coordinates. We also have the constant `a = -1` implied. Let
        // us rewrite the procedure of doubling (x, y, z) to produce (X, Y, Z)
        // as follows:
        //
        // B = (x + y)^2
        // C = x^2
        // D = y^2
        // F = D - C
        // H = 2 * z^2
        // J = F - H
        // X = (B - C - D) * J
        // Y = F * (- C - D)
        // Z = F * J
        //
        // If we compute K = D + C, we can rewrite this:
        //
        // B = (x + y)^2
        // C = x^2
        // D = y^2
        // F = D - C
        // K = D + C
        // H = 2 * z^2
        // J = F - H
        // X = (B - K) * J
        // Y = F * (-K)
        // Z = F * J
        //
        // In order to avoid the unnecessary negation of K,
        // we will negate J, transforming the result into
        // an equivalent point with a negated z-coordinate.
        //
        // B = (x + y)^2
        // C = x^2
        // D = y^2
        // F = D - C
        // K = D + C
        // H = 2 * z^2
        // J = H - F
        // X = (B - K) * J
        // Y = F * K
        // Z = F * J
        //
        // Let us rename some variables to simplify:
        //
        // XY2 = (x + y)^2
        // XX = x^2
        // YY = y^2
        // YYmXX = YY - XX
        // YYpXX = YY + XX
        // ZZ2 = 2 * z^2
        // J = ZZ2 - YYmXX
        // X = (XY2 - YYpXX) * J
        // Y = YYmXX * YYXX
        // Z = YYmXX * J
        //
        // We wish to obtain two factors of T = XY / Z.
        //
        // XY / Z
        // =
        // (XY2 - YYpXX) * (ZZ2 - VVmUU) * YYmXX * YYpXX / YYmXX / (ZZ2 - YYmXX)
        // =
        // (XY2 - YYpXX) * YYmXX * YYpXX / YYmXX
        // =
        // (XY2 - YYpXX) * YYpXX
        //
        // and so we have that T1 = (XY2 - YYpXX) and T2 = YYpXX.

        let xx = self.x.square();
        let yy = self.y.square();
        let zz2 = self.z.square().double();
        let xy2 = (&self.x + &self.y).square();
        let yy_plus_xx = &yy + &xx;
        let yy_minus_xx = &yy - &xx;

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            x: &xy2 - &yy_plus_xx,
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: &zz2 - &yy_minus_xx,
        }
        .into_extended()
    }

    #[inline]
    fn multiply(self, by: &[u8; 32]) -> Self {
        self.to_niels().multiply(by)
    }

    /// This is only for debugging purposes and not
    /// exposed in the public API. Checks that this
    /// point is on the curve.
    #[cfg(test)]
    fn is_on_curve_vartime(&self) -> bool {
        let affine = JubJubAffine::from(*self);

        self.z != BlsScalar::zero()
            && affine.is_on_curve_vartime()
            && (affine.x * affine.y * self.z == self.t1 * self.t2)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a JubJubExtended {
    type Output = JubJubExtended;

    fn mul(self, other: &'b Fr) -> JubJubExtended {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative!(JubJubExtended, Fr);

impl<'a, 'b> Add<&'b ExtendedNielsPoint> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: &'b ExtendedNielsPoint) -> JubJubExtended {
        // We perform addition in the extended coordinates. Here we use
        // a formula presented by Hisil, Wong, Carter and Dawson in
        // "Twisted Edward Curves Revisited" which only requires 8M.
        //
        // A = (Y1 - X1) * (Y2 - X2)
        // B = (Y1 + X1) * (Y2 + X2)
        // C = 2d * T1 * T2
        // D = 2 * Z1 * Z2
        // E = B - A
        // F = D - C
        // G = D + C
        // H = B + A
        // X3 = E * F
        // Y3 = G * H
        // Z3 = F * G
        // T3 = E * H

        let a = (&self.y - &self.x) * &other.y_minus_x;
        let b = (&self.y + &self.x) * &other.y_plus_x;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = (&self.z * &other.z).double();

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            x: &b - &a,
            y: &b + &a,
            z: &d + &c,
            t: &d - &c,
        }
        .into_extended()
    }
}

impl<'a, 'b> Sub<&'b ExtendedNielsPoint> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: &'b ExtendedNielsPoint) -> JubJubExtended {
        let a = (&self.y - &self.x) * &other.y_plus_x;
        let b = (&self.y + &self.x) * &other.y_minus_x;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = (&self.z * &other.z).double();

        CompletedPoint {
            x: &b - &a,
            y: &b + &a,
            z: &d - &c,
            t: &d + &c,
        }
        .into_extended()
    }
}

impl_binops_additive!(JubJubExtended, ExtendedNielsPoint);

impl<'a, 'b> Add<&'b AffineNielsPoint> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: &'b AffineNielsPoint) -> JubJubExtended {
        // This is identical to the addition formula for `ExtendedNielsPoint`,
        // except we can assume that `other.z` is one, so that we perform
        // 7 multiplications.

        let a = (&self.y - &self.x) * &other.y_minus_x;
        let b = (&self.y + &self.x) * &other.y_plus_x;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = self.z.double();

        // The remaining arithmetic is exactly the process of converting
        // from a completed point to an extended point.
        CompletedPoint {
            x: &b - &a,
            y: &b + &a,
            z: &d + &c,
            t: &d - &c,
        }
        .into_extended()
    }
}

impl<'a, 'b> Sub<&'b AffineNielsPoint> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: &'b AffineNielsPoint) -> JubJubExtended {
        let a = (&self.y - &self.x) * &other.y_plus_x;
        let b = (&self.y + &self.x) * &other.y_minus_x;
        let c = &self.t1 * &self.t2 * &other.t2d;
        let d = self.z.double();

        CompletedPoint {
            x: &b - &a,
            y: &b + &a,
            z: &d - &c,
            t: &d + &c,
        }
        .into_extended()
    }
}

impl_binops_additive!(JubJubExtended, AffineNielsPoint);

impl<'a, 'b> Add<&'b JubJubExtended> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[inline]
    fn add(self, other: &'b JubJubExtended) -> JubJubExtended {
        self + other.to_niels()
    }
}

impl<'a, 'b> Sub<&'b JubJubExtended> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[inline]
    fn sub(self, other: &'b JubJubExtended) -> JubJubExtended {
        self - other.to_niels()
    }
}

impl_binops_additive!(JubJubExtended, JubJubExtended);

impl<'a, 'b> Add<&'b JubJubAffine> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[inline]
    fn add(self, other: &'b JubJubAffine) -> JubJubExtended {
        self + other.to_niels()
    }
}

impl<'a, 'b> Sub<&'b JubJubAffine> for &'a JubJubExtended {
    type Output = JubJubExtended;

    #[inline]
    fn sub(self, other: &'b JubJubAffine) -> JubJubExtended {
        self - other.to_niels()
    }
}

impl_binops_additive!(JubJubExtended, JubJubAffine);

/// This is a "completed" point produced during a point doubling or
/// addition routine. These points exist in the `(X:Z, Y:T)` model
/// of the curve. This is not exposed in the API because it is
/// an implementation detail.
struct CompletedPoint {
    x: BlsScalar,
    y: BlsScalar,
    z: BlsScalar,
    t: BlsScalar,
}

impl CompletedPoint {
    /// This converts a completed point into an extended point by
    /// homogenizing:
    ///
    /// (x/z, y/t) = (x/z * t/t, y/t * z/z) = (xt/zt, yz/zt)
    ///
    /// The resulting T coordinate is xtyz/zt = xy, and so
    /// T1 = x, T2 = y, without loss of generality.
    #[inline]
    fn into_extended(self) -> JubJubExtended {
        JubJubExtended {
            x: &self.x * &self.t,
            y: &self.y * &self.z,
            z: &self.z * &self.t,
            t1: self.x,
            t2: self.y,
        }
    }
}

impl Default for JubJubAffine {
    /// Returns the identity.
    fn default() -> JubJubAffine {
        JubJubAffine::identity()
    }
}

impl Default for JubJubExtended {
    /// Returns the identity.
    fn default() -> JubJubExtended {
        JubJubExtended::identity()
    }
}

/// This takes a mutable slice of `JubJubExtended`s and "normalizes" them using
/// only a single inversion for the entire batch. This normalization results in
/// all of the points having a Z-coordinate of one. Further, an iterator is
/// returned which can be used to obtain `JubJubAffine`s for each element in the
/// slice.
///
/// This costs 5 multiplications per element, and a field inversion.
pub fn batch_normalize<'a>(
    y: &'a mut [JubJubExtended],
) -> impl Iterator<Item = JubJubAffine> + 'a {
    let mut acc = BlsScalar::one();
    for p in y.iter_mut() {
        // We use the `t1` field of `JubJubExtended` to store the product
        // of previous z-coordinates seen.
        p.t1 = acc;
        acc *= &p.z;
    }

    // This is the inverse, as all z-coordinates are nonzero.
    acc = acc.invert().unwrap();

    for p in y.iter_mut().rev() {
        let mut q = *p;

        // Compute tmp = 1/z
        let tmp = q.t1 * acc;

        // Cancel out z-coordinate in denominator of `acc`
        acc *= &q.z;

        // Set the coordinates to the correct value
        q.x *= &tmp; // Multiply by 1/z
        q.y *= &tmp; // Multiply by 1/z
        q.z = BlsScalar::one(); // z-coordinate is now one
        q.t1 = q.x;
        q.t2 = q.y;

        *p = q;
    }

    // All extended points are now normalized, but the type
    // doesn't encode this fact. Let us offer affine points
    // to the caller.

    y.iter().map(|p| JubJubAffine { x: p.x, y: p.y })
}

#[test]
fn test_is_on_curve_var() {
    assert!(JubJubAffine::identity().is_on_curve_vartime());
}

#[test]
fn test_affine_point_generator_has_order_p() {
    assert_eq!(GENERATOR.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_extended_point_generator_has_order_p() {
    assert_eq!(GENERATOR_EXTENDED.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_affine_point_generator_nums_has_order_p() {
    assert_eq!(GENERATOR_NUMS.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_affine_point_generator_is_not_identity() {
    assert_ne!(
        JubJubExtended::from(GENERATOR.mul_by_cofactor()),
        JubJubExtended::identity()
    );
}

#[test]
fn test_extended_point_generator_is_not_identity() {
    assert_ne!(
        GENERATOR_EXTENDED.mul_by_cofactor(),
        JubJubExtended::identity()
    );
}

#[test]
fn test_affine_point_generator_nums_is_not_identity() {
    assert_ne!(
        JubJubExtended::from(GENERATOR_NUMS.mul_by_cofactor()),
        JubJubExtended::identity()
    );
}

#[test]
fn test_d_is_non_quadratic_residue() {
    assert!(EDWARDS_D.sqrt().is_none().unwrap_u8() == 1);
    assert!((-EDWARDS_D).sqrt().is_none().unwrap_u8() == 1);
    assert!((-EDWARDS_D).invert().unwrap().sqrt().is_none().unwrap_u8() == 1);
}

#[test]
fn test_affine_niels_point_identity() {
    assert_eq!(
        AffineNielsPoint::identity().y_plus_x,
        JubJubAffine::identity().to_niels().y_plus_x
    );
    assert_eq!(
        AffineNielsPoint::identity().y_minus_x,
        JubJubAffine::identity().to_niels().y_minus_x
    );
    assert_eq!(
        AffineNielsPoint::identity().t2d,
        JubJubAffine::identity().to_niels().t2d
    );
}

#[test]
fn test_extended_niels_point_identity() {
    assert_eq!(
        ExtendedNielsPoint::identity().y_plus_x,
        JubJubExtended::identity().to_niels().y_plus_x
    );
    assert_eq!(
        ExtendedNielsPoint::identity().y_minus_x,
        JubJubExtended::identity().to_niels().y_minus_x
    );
    assert_eq!(
        ExtendedNielsPoint::identity().z,
        JubJubExtended::identity().to_niels().z
    );
    assert_eq!(
        ExtendedNielsPoint::identity().t2d,
        JubJubExtended::identity().to_niels().t2d
    );
}

#[test]
fn test_assoc() {
    let p = JubJubExtended::from(JubJubAffine {
        x: BlsScalar::from_raw([
            0x81c571e5d883cfb0,
            0x049f7a686f147029,
            0xf539c860bc3ea21f,
            0x4284715b7ccc8162,
        ]),
        y: BlsScalar::from_raw([
            0xbf096275684bb8ca,
            0xc7ba245890af256d,
            0x59119f3e86380eb0,
            0x3793de182f9fb1d2,
        ]),
    })
    .mul_by_cofactor();
    assert!(p.is_on_curve_vartime());

    assert_eq!(
        (p * Fr::from(1000u64)) * Fr::from(3938u64),
        p * (Fr::from(1000u64) * Fr::from(3938u64)),
    );
}

#[test]
fn test_batch_normalize() {
    let mut p = JubJubExtended::from(JubJubAffine {
        x: BlsScalar::from_raw([
            0x81c571e5d883cfb0,
            0x049f7a686f147029,
            0xf539c860bc3ea21f,
            0x4284715b7ccc8162,
        ]),
        y: BlsScalar::from_raw([
            0xbf096275684bb8ca,
            0xc7ba245890af256d,
            0x59119f3e86380eb0,
            0x3793de182f9fb1d2,
        ]),
    })
    .mul_by_cofactor();

    let mut y = vec![];
    for _ in 0..10 {
        y.push(p);
        p = p.double();
    }

    for p in &y {
        assert!(p.is_on_curve_vartime());
    }

    let expected: std::vec::Vec<_> =
        y.iter().map(|p| JubJubAffine::from(*p)).collect();
    let result1: std::vec::Vec<_> = batch_normalize(&mut y).collect();
    for i in 0..10 {
        assert!(expected[i] == result1[i]);
        assert!(y[i].is_on_curve_vartime());
        assert!(JubJubAffine::from(y[i]) == expected[i]);
    }
    let result2: std::vec::Vec<_> = batch_normalize(&mut y).collect();
    for i in 0..10 {
        assert!(expected[i] == result2[i]);
        assert!(y[i].is_on_curve_vartime());
        assert!(JubJubAffine::from(y[i]) == expected[i]);
    }
}

#[cfg(test)]
const FULL_GENERATOR: JubJubAffine = JubJubAffine::from_raw_unchecked(
    BlsScalar::from_raw([
        0xe4b3d35df1a7adfe,
        0xcaf55d1b29bf81af,
        0x8b0f03ddd60a8187,
        0x62edcbb8bf3787c8,
    ]),
    BlsScalar::from_raw([0xb, 0x0, 0x0, 0x0]),
);

#[cfg(test)]
const EIGHT_TORSION: [JubJubAffine; 8] = [
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xd92e6a7927200d43,
            0x7aa41ac43dae8582,
            0xeaaae086a16618d1,
            0x71d4df38ba9e7973,
        ]),
        BlsScalar::from_raw([
            0xff0d2068eff496dd,
            0x9106ee90f384a4a1,
            0x16a13035ad4d7266,
            0x4958bdb21966982e,
        ]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xfffeffff00000001,
            0x67baa40089fb5bfe,
            0xa5e80b39939ed334,
            0x73eda753299d7d47,
        ]),
        BlsScalar::from_raw([0x0, 0x0, 0x0, 0x0]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xd92e6a7927200d43,
            0x7aa41ac43dae8582,
            0xeaaae086a16618d1,
            0x71d4df38ba9e7973,
        ]),
        BlsScalar::from_raw([
            0xf2df96100b6924,
            0xc2b6b5720c79b75d,
            0x1c98a7d25c54659e,
            0x2a94e9a11036e51a,
        ]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([0x0, 0x0, 0x0, 0x0]),
        BlsScalar::from_raw([
            0xffffffff00000000,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0x26d19585d8dff2be,
            0xd919893ec24fd67c,
            0x488ef781683bbf33,
            0x218c81a6eff03d4,
        ]),
        BlsScalar::from_raw([
            0xf2df96100b6924,
            0xc2b6b5720c79b75d,
            0x1c98a7d25c54659e,
            0x2a94e9a11036e51a,
        ]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0x1000000000000,
            0xec03000276030000,
            0x8d51ccce760304d0,
            0x0,
        ]),
        BlsScalar::from_raw([0x0, 0x0, 0x0, 0x0]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0x26d19585d8dff2be,
            0xd919893ec24fd67c,
            0x488ef781683bbf33,
            0x218c81a6eff03d4,
        ]),
        BlsScalar::from_raw([
            0xff0d2068eff496dd,
            0x9106ee90f384a4a1,
            0x16a13035ad4d7266,
            0x4958bdb21966982e,
        ]),
    ),
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([0x0, 0x0, 0x0, 0x0]),
        BlsScalar::from_raw([0x1, 0x0, 0x0, 0x0]),
    ),
];

#[test]
fn find_eight_torsion() {
    let g = JubJubExtended::from(FULL_GENERATOR);
    assert!(g.is_small_order().unwrap_u8() == 0);
    let g = g.multiply(&FR_MODULUS_BYTES);
    assert!(g.is_small_order().unwrap_u8() == 1);

    let mut cur = g;

    for (i, point) in EIGHT_TORSION.iter().enumerate() {
        let tmp = JubJubAffine::from(cur);
        if &tmp != point {
            panic!("{}th torsion point should be {:?}", i, tmp);
        }

        cur += &g;
    }
}

#[test]
fn find_curve_generator() {
    let mut trial_bytes = [0; 32];
    for _ in 0..255 {
        let a = JubJubAffine::from_bytes(&trial_bytes);
        if a.is_ok() {
            let a = a.unwrap();
            assert!(a.is_on_curve_vartime());
            let b = JubJubExtended::from(a);
            let b = b.multiply(&FR_MODULUS_BYTES);
            assert!(b.is_small_order().unwrap_u8() == 1);
            let b = b.double();
            assert!(b.is_small_order().unwrap_u8() == 1);
            let b = b.double();
            assert!(b.is_small_order().unwrap_u8() == 1);
            if b.is_identity().unwrap_u8() == 0 {
                let b = b.double();
                assert!(b.is_small_order().unwrap_u8() == 1);
                assert!(b.is_identity().unwrap_u8() == 1);
                assert_eq!(FULL_GENERATOR, a);
                assert!(a.mul_by_cofactor().is_torsion_free().unwrap_u8() == 1);
                return;
            }
        }

        trial_bytes[0] += 1;
    }

    panic!("should have found a generator of the curve");
}

#[test]
fn test_small_order() {
    for point in EIGHT_TORSION.iter() {
        assert!(point.is_small_order().unwrap_u8() == 1);
    }
}

#[ignore]
#[test]
fn second_gen_nums() {
    use blake2::{Blake2b, Digest};
    let generator_bytes = GENERATOR.to_bytes();
    let mut counter = 0u64;
    let mut array = [0u8; 32];
    loop {
        let mut hasher = Blake2b::new();
        hasher.update(generator_bytes);
        hasher.update(counter.to_le_bytes());
        let res = hasher.finalize();
        array.copy_from_slice(&res[0..32]);
        if JubJubAffine::from_bytes(&array).is_ok()
            && JubJubAffine::from_bytes(&array)
                .unwrap()
                .is_prime_order()
                .unwrap_u8()
                == 1
        {
            assert!(
                GENERATOR_NUMS == JubJubAffine::from_bytes(&array).unwrap()
            );
        }
        counter += 1;
    }
}

#[test]
fn test_is_identity() {
    let a = EIGHT_TORSION[0].mul_by_cofactor();
    let b = EIGHT_TORSION[1].mul_by_cofactor();

    assert_eq!(a.x, b.x);
    assert_eq!(a.y, a.z);
    assert_eq!(b.y, b.z);
    assert!(a.y != b.y);
    assert!(a.z != b.z);

    assert!(a.is_identity().unwrap_u8() == 1);
    assert!(b.is_identity().unwrap_u8() == 1);

    for point in EIGHT_TORSION.iter() {
        assert!(point.mul_by_cofactor().is_identity().unwrap_u8() == 1);
    }
}

#[test]
fn test_mul_consistency() {
    let a = Fr([
        0x21e61211d9934f2e,
        0xa52c058a693c3e07,
        0x9ccb77bfb12d6360,
        0x07df2470ec94398e,
    ]);
    let b = Fr([
        0x03336d1cbe19dbe0,
        0x0153618f6156a536,
        0x2604c9e1fc3c6b15,
        0x04ae581ceb028720,
    ]);
    let c = Fr([
        0xd7abf5bb24683f4c,
        0x9d7712cc274b7c03,
        0x973293db9683789f,
        0x0b677e29380a97a7,
    ]);
    assert_eq!(a * b, c);
    let p = JubJubExtended::from(JubJubAffine {
        x: BlsScalar::from_raw([
            0x81c571e5d883cfb0,
            0x049f7a686f147029,
            0xf539c860bc3ea21f,
            0x4284715b7ccc8162,
        ]),
        y: BlsScalar::from_raw([
            0xbf096275684bb8ca,
            0xc7ba245890af256d,
            0x59119f3e86380eb0,
            0x3793de182f9fb1d2,
        ]),
    })
    .mul_by_cofactor();
    assert_eq!(p * c, (p * a) * b);

    // Test Mul implemented on ExtendedNielsPoint
    assert_eq!(p * c, (p.to_niels() * a) * b);
    assert_eq!(p.to_niels() * c, (p * a) * b);
    assert_eq!(p.to_niels() * c, (p.to_niels() * a) * b);

    // Test Mul implemented on AffineNielsPoint
    let p_affine_niels = JubJubAffine::from(p).to_niels();
    assert_eq!(p * c, (p_affine_niels * a) * b);
    assert_eq!(p_affine_niels * c, (p * a) * b);
    assert_eq!(p_affine_niels * c, (p_affine_niels * a) * b);
}

#[test]
fn test_serialization_consistency() {
    let gen = FULL_GENERATOR.mul_by_cofactor();
    let mut p = gen;

    let y = vec![
        [
            203, 85, 12, 213, 56, 234, 12, 193, 19, 132, 128, 64, 142, 110,
            170, 185, 179, 108, 97, 63, 13, 211, 247, 120, 79, 219, 110, 234,
            131, 123, 19, 215,
        ],
        [
            113, 154, 240, 230, 224, 198, 208, 170, 104, 15, 59, 126, 151, 222,
            233, 195, 203, 195, 167, 129, 89, 121, 240, 142, 51, 166, 64, 250,
            184, 202, 154, 177,
        ],
        [
            197, 41, 93, 209, 203, 55, 164, 174, 88, 0, 90, 199, 1, 156, 149,
            141, 240, 29, 14, 82, 86, 225, 126, 129, 186, 157, 148, 162, 219,
            51, 156, 199,
        ],
        [
            182, 117, 250, 241, 81, 196, 199, 227, 151, 74, 243, 17, 221, 97,
            200, 139, 192, 83, 231, 35, 214, 14, 95, 69, 130, 201, 4, 116, 177,
            19, 179, 0,
        ],
        [
            118, 41, 29, 200, 60, 189, 119, 252, 78, 40, 230, 18, 208, 221, 38,
            214, 176, 250, 4, 10, 77, 101, 26, 216, 193, 198, 226, 84, 25, 177,
            230, 185,
        ],
        [
            226, 189, 227, 208, 112, 117, 136, 98, 72, 38, 211, 167, 254, 82,
            174, 113, 112, 166, 138, 171, 166, 113, 52, 251, 129, 197, 138, 45,
            195, 7, 61, 140,
        ],
        [
            38, 198, 156, 196, 146, 225, 55, 163, 138, 178, 157, 128, 115, 135,
            204, 215, 0, 33, 171, 20, 60, 32, 142, 209, 33, 233, 125, 146, 207,
            12, 16, 24,
        ],
        [
            17, 187, 231, 83, 165, 36, 232, 184, 140, 205, 195, 252, 166, 85,
            59, 86, 3, 226, 211, 67, 179, 29, 238, 181, 102, 142, 58, 63, 57,
            89, 174, 138,
        ],
        [
            210, 159, 80, 16, 181, 39, 221, 204, 224, 144, 145, 79, 54, 231, 8,
            140, 142, 216, 93, 190, 183, 116, 174, 63, 33, 242, 177, 118, 148,
            40, 241, 203,
        ],
        [
            0, 143, 107, 102, 149, 187, 27, 124, 18, 10, 98, 28, 113, 123, 121,
            185, 29, 152, 14, 130, 149, 28, 87, 35, 135, 135, 153, 54, 112, 53,
            54, 68,
        ],
        [
            178, 131, 85, 160, 214, 51, 208, 157, 196, 152, 247, 93, 202, 56,
            81, 239, 155, 122, 59, 188, 237, 253, 11, 169, 208, 236, 12, 4,
            163, 211, 88, 97,
        ],
        [
            246, 194, 231, 195, 159, 101, 180, 133, 80, 21, 185, 220, 195, 115,
            144, 12, 90, 150, 44, 117, 8, 156, 168, 248, 206, 41, 60, 82, 67,
            75, 57, 67,
        ],
        [
            212, 205, 171, 153, 113, 16, 194, 241, 224, 43, 177, 110, 190, 248,
            22, 201, 208, 166, 2, 83, 134, 130, 85, 129, 166, 136, 185, 191,
            163, 38, 54, 10,
        ],
        [
            8, 60, 190, 39, 153, 222, 119, 23, 142, 237, 12, 110, 146, 9, 19,
            219, 143, 64, 161, 99, 199, 77, 39, 148, 70, 213, 246, 227, 150,
            178, 237, 178,
        ],
        [
            11, 114, 217, 160, 101, 37, 100, 220, 56, 114, 42, 31, 138, 33, 84,
            157, 214, 167, 73, 233, 115, 81, 124, 134, 15, 31, 181, 60, 184,
            130, 175, 159,
        ],
        [
            141, 238, 235, 202, 241, 32, 210, 10, 127, 230, 54, 31, 146, 80,
            247, 9, 107, 124, 0, 26, 203, 16, 237, 34, 214, 147, 133, 15, 29,
            236, 37, 88,
        ],
    ];

    for expected_serialized in y {
        assert!(p.is_on_curve_vartime());
        let affine = JubJubAffine::from(p);
        let serialized = affine.to_bytes();
        let deserialized = JubJubAffine::from_bytes(&serialized).unwrap();
        assert_eq!(affine, deserialized);
        assert_eq!(expected_serialized, serialized);
        p = p + &gen;
    }
}

/// Compute a shared secret `secret · public` using DHKE protocol
pub fn dhke(secret: &Fr, public: &JubJubExtended) -> JubJubAffine {
    public.mul(secret).into()
}
