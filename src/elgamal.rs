use crate::{ExtendedPoint, Fr};

use core::ops::{Add, AddAssign, Sub, SubAssign};

/// Tuple for assymetric encryption using ElGamal algorithm.
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct ElgamalCipher {
    gamma: ExtendedPoint,
    delta: ExtendedPoint,
}

impl ElgamalCipher {
    /// [`ElgamalCipher`] constructor
    pub fn new(gamma: ExtendedPoint, delta: ExtendedPoint) -> Self {
        Self { gamma, delta }
    }

    /// Getter for the gamma public key
    pub fn gamma(&self) -> &ExtendedPoint {
        &self.gamma
    }

    /// Getter for the delta ciphertext
    pub fn delta(&self) -> &ExtendedPoint {
        &self.delta
    }

    /// Uses assymetric encryption to return a cipher construction.
    ///
    /// The decryption will expect the secret of `public`.
    pub fn encrypt(
        secret: &Fr,
        public: &ExtendedPoint,
        generator: &ExtendedPoint,
        message: &ExtendedPoint,
    ) -> Self {
        let gamma = generator * secret;
        let delta = message + public * secret;

        Self::new(gamma, delta)
    }

    /// Perform the decryption with the provided secret.
    pub fn decrypt(&self, secret: &Fr) -> ExtendedPoint {
        self.delta - self.gamma * secret
    }
}

impl Add for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, other: &ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher::new(self.gamma + other.gamma, self.delta + other.delta)
    }
}

impl Add for ElgamalCipher {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl AddAssign for ElgamalCipher {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn sub(self, other: &ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher::new(self.gamma - other.gamma, self.delta - other.delta)
    }
}

impl Sub for ElgamalCipher {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        &self - &other
    }
}

impl SubAssign for ElgamalCipher {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

#[cfg(test)]
mod tests {
    use super::ElgamalCipher;
    use crate::{ExtendedPoint, Fr, GENERATOR_EXTENDED};

    fn gen() -> (Fr, ExtendedPoint, Fr, ExtendedPoint) {
        let a = Fr::random(&mut rand::thread_rng());
        let a_g = GENERATOR_EXTENDED * a;

        let b = Fr::random(&mut rand::thread_rng());
        let b_g = GENERATOR_EXTENDED * b;

        (a, a_g, b, b_g)
    }

    #[test]
    fn encrypt() {
        let (a, _, b, b_g) = gen();

        let m = Fr::random(&mut rand::thread_rng());
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);
        let decrypt = cipher.decrypt(&b);

        assert_eq!(m, decrypt);
    }

    #[test]
    fn wrong_key() {
        let (a, _, b, b_g) = gen();

        let m = Fr::random(&mut rand::thread_rng());
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);

        let wrong = b - Fr::one();
        let decrypt = cipher.decrypt(&wrong);

        assert_ne!(m, decrypt);
    }

    #[test]
    fn homomorphic() {
        let (a, _, b, b_g) = gen();

        let mut m = [Fr::zero(); 10];
        m.iter_mut()
            .for_each(|x| *x = Fr::random(&mut rand::thread_rng()));

        let mut m_g = [ExtendedPoint::default(); 10];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] + m[1] + m[2] + m[3] - m[4] - m[5] - m[6];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher = [ElgamalCipher::default(); 10];
        cipher.iter_mut().zip(m_g.iter()).for_each(|(x, y)| {
            *x = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, y)
        });

        let mut hom_cipher = cipher[0] + cipher[1];
        hom_cipher += cipher[2];
        hom_cipher = &hom_cipher + &cipher[3];
        hom_cipher = hom_cipher - cipher[4];
        hom_cipher -= cipher[5];
        hom_cipher = &hom_cipher - &cipher[6];

        let hom_decrypt = hom_cipher.decrypt(&b);

        assert_eq!(result, hom_decrypt);
    }
}
