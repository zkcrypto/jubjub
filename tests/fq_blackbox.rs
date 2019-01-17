extern crate jubjub;

extern crate rand;

use jubjub::*;
use rand::rngs::OsRng;

const NUM_TO_CHECK: u32 = 20;

fn new_os_rng() -> OsRng {
    match OsRng::new() {
        Ok(rng) => rng,
        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
    }
}

#[test]
fn test_associativity() {
    let mut os_rng = new_os_rng();
    for _ in 0..NUM_TO_CHECK {
        let a = Fq::random(&mut os_rng);
        let b = Fq::random(&mut os_rng);
        let c = Fq::random(&mut os_rng);
        assert_eq!((a * b) * c, a * (b * c))
    }
}

#[test]
fn test_identity() {
    let mut os_rng = new_os_rng();
    for _ in 0..NUM_TO_CHECK {
        let a = Fq::random(&mut os_rng);
        assert_eq!(a, a * Fq::one());
        assert_eq!(a, Fq::one() * a);
    }
}

#[test]
fn test_inverse() {
    let mut os_rng = new_os_rng();
    for _ in 0..NUM_TO_CHECK {
        let a = Fq::random(&mut os_rng);
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
    let mut os_rng = new_os_rng();
    for _ in 0..NUM_TO_CHECK {
        let a = Fq::random(&mut os_rng);
        let b = Fq::random(&mut os_rng);
        assert_eq!(a * b, b * a);
    }
}
