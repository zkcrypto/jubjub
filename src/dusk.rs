// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
extern crate alloc;

use core::ops::Mul;
use ff::Field;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

pub use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as BytesError, Serializable};

use crate::{Fr, JubJubAffine, JubJubExtended, EDWARDS_D};

/// Compute a shared secret `secret · public` using DHKE protocol
pub fn dhke(secret: &Fr, public: &JubJubExtended) -> JubJubAffine {
    public.mul(secret).into()
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
///     y = 0x0000000000000000000000000000000000000000000000000000000000000012
pub const GENERATOR: JubJubAffine = JubJubAffine {
    u: BlsScalar::from_raw([
        0x4df7b7ffec7beaca,
        0x2e3ebb21fd6c54ed,
        0xf1fbf02d0fd6cce6,
        0x3fd2814c43ac65a6,
    ]),
    v: BlsScalar::from_raw([
        0x0000000000000012,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]),
};

/// [`GENERATOR`] in [`JubJubExtended`] form
pub const GENERATOR_EXTENDED: JubJubExtended = JubJubExtended {
    u: GENERATOR.u,
    v: GENERATOR.v,
    z: BlsScalar::one(),
    t1: GENERATOR.u,
    t2: GENERATOR.v,
};

/// GENERATOR NUMS which is obtained following the specs in:
/// https://app.gitbook.com/@dusk-network/s/specs/specifications/poseidon/pedersen-commitment-scheme
/// The counter = 18 and the hash function used to compute it was blake2b
/// Using:
///     x = 0x5e67b8f316f414f7bd9514c773fd4456931e316a39fe4541921710179df76377
///     y = 0x43d80eb3b2f3eb1b7b162dbeeb3b34fd9949ba0f82a5507a6705b707162e3ef8
pub const GENERATOR_NUMS: JubJubAffine = JubJubAffine {
    u: BlsScalar::from_raw([
        0x921710179df76377,
        0x931e316a39fe4541,
        0xbd9514c773fd4456,
        0x5e67b8f316f414f7,
    ]),
    v: BlsScalar::from_raw([
        0x6705b707162e3ef8,
        0x9949ba0f82a5507a,
        0x7b162dbeeb3b34fd,
        0x43d80eb3b2f3eb1b,
    ]),
};

/// [`GENERATOR_NUMS`] in [`JubJubExtended`] form
pub const GENERATOR_NUMS_EXTENDED: JubJubExtended = JubJubExtended {
    u: GENERATOR_NUMS.u,
    v: GENERATOR_NUMS.v,
    z: BlsScalar::one(),
    t1: GENERATOR_NUMS.u,
    t2: GENERATOR_NUMS.v,
};

impl Serializable<32> for JubJubAffine {
    type Error = BytesError;

    /// Attempts to interpret a byte representation of an
    /// affine point, failing if the element is not on
    /// the curve or non-canonical.
    ///
    /// NOTE: ZIP 216 is enabled by default and the only way to interact
    /// with serialization.
    /// See: <https://zips.z.cash/zip-0216> for more details.
    fn from_bytes(b: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut b = *b;

        // Grab the sign bit from the representation
        let sign = b[31] >> 7;

        // Mask away the sign bit
        b[31] &= 0b0111_1111;

        // Interpret what remains as the y-coordinate
        let v = <BlsScalar as Serializable<32>>::from_bytes(&b)?;

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

        let v2 = v.square();

        Option::from(
            ((v2 - BlsScalar::one())
                * ((BlsScalar::one() + EDWARDS_D * v2)
                    .invert()
                    .unwrap_or(BlsScalar::zero())))
            .sqrt()
            .and_then(|u| {
                // Fix the sign of `x` if necessary
                let flip_sign = Choice::from((u.to_bytes()[0] ^ sign) & 1);
                let u = BlsScalar::conditional_select(&u, &-u, flip_sign);
                // If x == 0, flip_sign == sign_bit. We therefore want to
                // reject the encoding as non-canonical
                // if all of the following occur:
                // - x == 0
                // - flip_sign == true
                let u_is_zero = u.ct_eq(&BlsScalar::zero());
                CtOption::new(JubJubAffine { u, v }, !(u_is_zero & flip_sign))
            }),
        )
        .ok_or(BytesError::InvalidData)
    }

    /// Converts this element into its byte representation.
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut tmp = self.v.to_bytes();
        let u = self.u.to_bytes();

        // Encode the sign of the x-coordinate in the most
        // significant bit.
        tmp[31] |= u[0] << 7;

        tmp
    }
}

impl JubJubExtended {
    /// Constructs an extended point (with `Z = 1`) from
    /// an affine point using the map `(x, y) => (x, y, 1, x, y)`.
    pub const fn from_affine(affine: JubJubAffine) -> Self {
        Self::from_raw_unchecked(
            affine.u,
            affine.v,
            BlsScalar::one(),
            affine.u,
            affine.v,
        )
    }

    /// Constructs an extended point from its raw internals
    pub const fn from_raw_unchecked(
        u: BlsScalar,
        v: BlsScalar,
        z: BlsScalar,
        t1: BlsScalar,
        t2: BlsScalar,
    ) -> Self {
        Self { u, v, z, t1, t2 }
    }

    /// Returns the `u`-coordinate of this point.
    pub const fn get_u(&self) -> BlsScalar {
        self.u
    }

    /// Returns the `v`-coordinate of this point.
    pub const fn get_v(&self) -> BlsScalar {
        self.v
    }

    /// Returns the `z`-coordinate of this point.
    pub const fn get_z(&self) -> BlsScalar {
        self.z
    }

    /// Returns the `t1`-coordinate of this point.
    pub const fn get_t1(&self) -> BlsScalar {
        self.t1
    }

    /// Returns the `t2`-coordinate of this point.
    pub const fn get_t2(&self) -> BlsScalar {
        self.t2
    }

    /// Returns two scalars suitable for hashing that represent the
    /// Extended Point.
    pub fn to_hash_inputs(&self) -> [BlsScalar; 2] {
        // The same JubJubAffine can have different JubJubExtended
        // representations, therefore we convert from Extended to Affine
        // before hashing, to ensure deterministic result
        let p = JubJubAffine::from(self);
        [p.u, p.v]
    }

    /// Hash an arbitrary slice of bytes to a point on the elliptic curve and
    /// in the prime order subgroup.
    ///
    /// This algorithm uses rejection sampling to hash to a point on the curve:
    /// The input together with a counter are hashed into an array of 32 bytes.
    /// If the hash is a canonical representation of a point on the curve and
    /// a member of the prime-order subgroup, we return it. If not, we increment
    /// the counter, hash and try to de-serialize again.
    /// This is the same algorithm we used to generate `GENERATOR_NUMS` as
    /// outlined [here](https://app.gitbook.com/@dusk-network/s/specs/specifications/poseidon/pedersen-commitment-scheme).
    ///
    /// **Note:** This implementation of `hash_to_point` is not constant time,
    /// in the long run we want to implement an algorithm outlined
    /// [here](https://datatracker.ietf.org/doc/html/rfc9380), but we start with
    /// this implementation in order to be able to use the API already.
    pub fn hash_to_point(input: &[u8]) -> Self {
        let mut counter = 0u64;
        let mut array = [0u8; 32];
        loop {
            let state = blake2b_simd::Params::new()
                .hash_length(32)
                .to_state()
                .update(input)
                .update(&counter.to_le_bytes())
                .finalize();

            array.copy_from_slice(&state.as_bytes()[..32]);

            // check if we hit a point on the curve
            if let Ok(point) =
                <JubJubAffine as Serializable<32>>::from_bytes(&array)
            {
                // check if this point is part of the correct subgroup and not
                // the identity
                if point.is_prime_order().into() {
                    return point.into();
                }
            }
            counter += 1
        }
    }
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
        if <JubJubAffine as Serializable<32>>::from_bytes(&array).is_ok()
            && <JubJubAffine as Serializable<32>>::from_bytes(&array)
                .unwrap()
                .is_prime_order()
                .unwrap_u8()
                == 1
        {
            assert!(
                GENERATOR_NUMS
                    == <JubJubAffine as Serializable<32>>::from_bytes(&array)
                        .unwrap()
            );
            break;
        }
        counter += 1;
    }
    assert_eq!(counter, 18);
}

#[cfg(all(test, feature = "alloc"))]
mod fuzz {
    use alloc::vec::Vec;

    use crate::ExtendedPoint;

    quickcheck::quickcheck! {
        fn prop_hash_to_point(bytes: Vec<u8>) -> bool {
            let point = ExtendedPoint::hash_to_point(&bytes);

            point.is_on_curve_vartime() && point.is_prime_order().into()
        }
    }
}
