mod common;

use common::{new_rng, MyRandom, NUM_BLACK_BOX_CHECKS};
use dusk_jubjub::*;

#[test]
fn test_to_and_from_bytes() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        assert_eq!(a, Fr::from_bytes(&Fr::to_bytes(&a)).unwrap());
    }
}

#[test]
fn test_additive_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        let b = Fr::new_random(&mut rng);
        let c = Fr::new_random(&mut rng);
        assert_eq!((a + b) + c, a + (b + c))
    }
}

#[test]
fn test_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        assert_eq!(a, a + Fr::zero());
        assert_eq!(a, Fr::zero() + a);
    }
}

#[test]
fn test_subtract_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        assert_eq!(a, a - Fr::zero());
        assert_eq!(a, Fr::zero() - -&a);
    }
}

#[test]
fn test_additive_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        let a_neg = -&a;
        assert_eq!(Fr::zero(), a + a_neg);
        assert_eq!(Fr::zero(), a_neg + a);
    }
}

#[allow(clippy::eq_op)]
#[test]
fn test_additive_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        let b = Fr::new_random(&mut rng);
        assert_eq!(a + b, b + a);
    }
}

#[test]
fn test_multiplicative_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        let b = Fr::new_random(&mut rng);
        let c = Fr::new_random(&mut rng);
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_multiplicative_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        assert_eq!(a, a * Fr::one());
        assert_eq!(a, Fr::one() * a);
    }
}

#[test]
fn test_multiplicative_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        if a == Fr::zero() {
            continue;
        }
        let a_inv = a.invert().unwrap();
        assert_eq!(Fr::one(), a * a_inv);
        assert_eq!(Fr::one(), a_inv * a);
    }
}

#[test]
fn test_multiplicative_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        let b = Fr::new_random(&mut rng);
        assert_eq!(a * b, b * a);
    }
}

#[test]
fn test_multiply_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = Fr::new_random(&mut rng);
        assert_eq!(Fr::zero(), Fr::zero() * a);
        assert_eq!(Fr::zero(), a * Fr::zero());
    }
}

#[test]
fn test_dhke() {
    let mut rng = new_rng();
    let g: JubJubExtended = GENERATOR.into();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = JubJubScalar::new_random(&mut rng);
        let b = JubJubScalar::new_random(&mut rng);

        let a_g = g * a;
        let b_g = g * b;

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
