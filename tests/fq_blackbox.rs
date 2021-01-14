mod common;

use common::{new_rng, MyRandom, NUM_BLACK_BOX_CHECKS};
use dusk_bytes::Serializable;
use dusk_jubjub::*;

#[test]
fn test_to_and_from_bytes() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        assert_eq!(a, BlsScalar::from_bytes(&BlsScalar::to_bytes(&a)).unwrap());
    }
}

#[test]
fn test_additive_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        let b = BlsScalar::new_random(&mut rng);
        let c = BlsScalar::new_random(&mut rng);
        assert_eq!((a + b) + c, a + (b + c))
    }
}

#[test]
fn test_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        assert_eq!(a, a + BlsScalar::zero());
        assert_eq!(a, BlsScalar::zero() + a);
    }
}

#[test]
fn test_subtract_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        assert_eq!(a, a - BlsScalar::zero());
        assert_eq!(a, BlsScalar::zero() - -&a);
    }
}

#[test]
fn test_additive_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        let a_neg = -&a;
        assert_eq!(BlsScalar::zero(), a + a_neg);
        assert_eq!(BlsScalar::zero(), a_neg + a);
    }
}

#[test]
fn test_additive_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        let b = BlsScalar::new_random(&mut rng);
        assert_eq!(a + b, b + a);
    }
}

#[test]
fn test_multiplicative_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        let b = BlsScalar::new_random(&mut rng);
        let c = BlsScalar::new_random(&mut rng);
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_multiplicative_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        assert_eq!(a, a * BlsScalar::one());
        assert_eq!(a, BlsScalar::one() * a);
    }
}

#[test]
fn test_multiplicative_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        if a == BlsScalar::zero() {
            continue;
        }
        let a_inv = a.invert().unwrap();
        assert_eq!(BlsScalar::one(), a * a_inv);
        assert_eq!(BlsScalar::one(), a_inv * a);
    }
}

#[test]
fn test_multiplicative_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        let b = BlsScalar::new_random(&mut rng);
        assert_eq!(a * b, b * a);
    }
}

#[test]
fn test_multiply_additive_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_BLACK_BOX_CHECKS {
        let a = BlsScalar::new_random(&mut rng);
        assert_eq!(BlsScalar::zero(), BlsScalar::zero() * a);
        assert_eq!(BlsScalar::zero(), a * BlsScalar::zero());
    }
}
