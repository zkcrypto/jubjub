mod common;

use core::ops::Mul;

use crate::BlsScalar;
use common::{new_rng, MyRandom, NUM_BLACK_BOX_CHECKS};
use dusk_bytes::Serializable;
use dusk_jubjub::*;

#[test]
fn test_to_and_from_bytes() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        assert_eq!(
            a,
            JubJubScalar::from_bytes(&JubJubScalar::to_bytes(&a)).unwrap()
        );
    }
}

#[test]
fn test_additive_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);
        let c = JubJubScalar::new_random(&mut rng);
        assert_eq!((a + b) + c, a + (b + c))
    }
}

#[test]
fn test_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        assert_eq!(a, a + JubJubScalar::zero());
        assert_eq!(a, JubJubScalar::zero() + a);
    }
}

#[test]
fn test_subtract_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        assert_eq!(a, a - JubJubScalar::zero());
        assert_eq!(a, JubJubScalar::zero() - -&a);
    }
}

#[test]
fn test_additive_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let a_neg = -&a;
        assert_eq!(JubJubScalar::zero(), a + a_neg);
        assert_eq!(JubJubScalar::zero(), a_neg + a);
    }
}

#[test]
fn test_additive_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);
        assert_eq!(a + b, b + a);
    }
}

#[test]
fn test_multiplicative_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);
        let c = JubJubScalar::new_random(&mut rng);
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_multiplicative_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        assert_eq!(a, a * JubJubScalar::one());
        assert_eq!(a, JubJubScalar::one() * a);
    }
}

#[test]
fn test_multiplicative_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        if a == JubJubScalar::zero() {
            continue;
        }
        let a_inv = a.invert().unwrap();
        assert_eq!(JubJubScalar::one(), a * a_inv);
        assert_eq!(JubJubScalar::one(), a_inv * a);
    }
}

#[test]
fn test_multiplicative_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);
        assert_eq!(a * b, b * a);
    }
}

#[test]
fn test_multiply_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        assert_eq!(JubJubScalar::zero(), JubJubScalar::zero() * a);
        assert_eq!(JubJubScalar::zero(), a * JubJubScalar::zero());
    }
}

#[test]
fn test_dhke() {
    let mut rng = new_rng();
    let g: JubJubExtended = GENERATOR.into();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);

        let a_g = g.mul(&a);
        let b_g = g.mul(&b);

        assert_eq!(dhke(&a, &b_g), dhke(&b, &a_g));
        assert_ne!(dhke(&a, &b_g), dhke(&b, &b_g));
    }
}
#[test]
fn test_from_jubjub_to_bls_scalar() {
    assert_eq!(
        BlsScalar::zero(),
        BlsScalar::from(JubJubScalar::zero()),
        "Scalar conversion from JubJub's zero to BLS' zero"
    );
    assert_eq!(
        BlsScalar::one(),
        BlsScalar::from(JubJubScalar::one()),
        "Scalar conversion from JubJub's one to BLS' one"
    );

    let jubjub_scalar = -JubJubScalar::one();
    let bls_scalar = BlsScalar::from(jubjub_scalar);

    assert_eq!(
        jubjub_scalar.to_bytes(),
        bls_scalar.to_bytes(),
        "Scalar conversion from JubJub's maximum number to BLS"
    );

    let bls_scalar = BlsScalar::from(77u64);
    let jubjub_scalar = JubJubScalar::from(77u64);

    assert_eq!(
        bls_scalar,
        BlsScalar::from(jubjub_scalar),
        "Scalar conversion from an arbitrary JubJub's number to BLS"
    );
}
