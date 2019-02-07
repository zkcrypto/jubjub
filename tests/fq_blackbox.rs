extern crate jubjub;

extern crate rand;
extern crate rand_xorshift;

use jubjub::*;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

const NUM_TO_CHECK: u32 = 2000;

fn new_rng() -> XorShiftRng {
    XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
}

#[test]
fn test_associativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_TO_CHECK {
        let a: Fq = rng.gen();
        let b: Fq = rng.gen();
        let c: Fq = rng.gen();
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_identity() {
    let mut rng = new_rng();
    for _ in 0..NUM_TO_CHECK {
        let a: Fq = rng.gen();
        assert_eq!(a, a * Fq::one());
        assert_eq!(a, Fq::one() * a);
    }
}

#[test]
fn test_inverse() {
    let mut rng = new_rng();
    for _ in 0..NUM_TO_CHECK {
        let a: Fq = rng.gen();
        if a == Fq::zero() {
            continue;
        }
        let a_inv = a.invert_nonzero();
        assert_eq!(Fq::one(), a * a_inv);
        assert_eq!(Fq::one(), a_inv * a);
    }
}

#[test]
fn test_commutativity() {
    let mut rng = new_rng();
    for _ in 0..NUM_TO_CHECK {
        let a: Fq = rng.gen();
        let b: Fq = rng.gen();
        assert_eq!(a * b, b * a);
    }
}
