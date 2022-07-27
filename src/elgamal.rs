use crate::{JubJubAffine, JubJubExtended, JubJubScalar};

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Tuple for assymetric encryption using ElGamal algorithm.
///
/// ## Example
///
/// ```ignore
/// use dusk_jubjub::elgamal::ElgamalCipher;
/// use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
///
/// fn main() {
///     // Bob's (sender) secret and message
///     let bob_secret = JubJubScalar::random(&mut rand::thread_rng());
///     let message = JubJubScalar::random(&mut rand::thread_rng());
///     let message = GENERATOR_EXTENDED * message;
///
///     // Alice's (receiver) secret and public
///     let alice_secret = JubJubScalar::random(&mut rand::thread_rng());
///     let alice_public = GENERATOR_EXTENDED * alice_secret;
///
///     let cipher = ElgamalCipher::encrypt(
///         &bob_secret,
///         &alice_public,
///         &GENERATOR_EXTENDED,
///         &message,
///     );
///     let decrypt = cipher.decrypt(&alice_secret);
///
///     assert_eq!(message, decrypt);
/// }
/// ```
///
/// 1. Let `p` and `G = α` be defined by the parameters of JubJub.
/// 2. Let `a` be Alice's secret, and `A = G · a`
/// 3. Let `b` be Bob's secret, and `B = G · b`
///
/// #### Encryption
/// Bob should do the following:
///
/// 1. Obtain Alice’s authentic public key `A`.
/// 2. Represent the message `M` as a point of JubJub defined such as `M = G ·m`
/// where `m` is a scalar in `JubJubScalar`.
/// 3. Compute `γ = G · b` and `δ = M + (A ·b)`.
/// 4. Send the ciphertext `c = (γ; δ)` to Alice.
///
/// #### Decryption
/// To recover plaintext `M` from `c`, Alice should do the following:
///
/// 1. Recover `M` by computing `δ - γ · a`.
///
/// #### Homomorphism
/// A function `f` is homomorphic when `f(a · b) = f(a) · f(b)`.
///
/// This implementation extends the homomorphic property of ElGamal to addition,
/// subtraction and multiplication.
///
/// The addition and subtraction are homomorphic with other [`ElgamalCipher`]
/// structures.
///
/// The multiplication is homomorphic with [`JubJubScalar`] scalars.
///
/// Being `E` the encrypt and `D` the decrypt functions, here follows an
/// example: `D{E[x * (a + b)]} == D{x * [E(a) + E(b)]}`
#[derive(Debug, Copy, Clone, PartialEq, Default)]
#[cfg_attr(feature = "rkyv-impl", derive(Archive, Serialize, Deserialize))]
pub struct ElgamalCipher {
    gamma: JubJubExtended,
    delta: JubJubExtended,
}

impl Serializable<64> for ElgamalCipher {
    type Error = BytesError;

    /// Serialize the cipher into bytes
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let gamma: JubJubAffine = self.gamma.into();
        let gamma = gamma.to_bytes();

        let delta: JubJubAffine = self.delta.into();
        let delta = delta.to_bytes();

        let mut bytes = [0u8; Self::SIZE];

        bytes[..32].copy_from_slice(&gamma);
        bytes[32..].copy_from_slice(&delta);

        bytes
    }

    /// Deserialize from a [`ElgamalCipher::to_bytes`] construction
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let gamma = JubJubAffine::from_slice(&bytes[..32])?;
        let delta = JubJubAffine::from_slice(&bytes[32..])?;
        let cipher = ElgamalCipher::new(gamma.into(), delta.into());
        Ok(cipher)
    }
}

impl ElgamalCipher {
    /// [`ElgamalCipher`] constructor
    pub fn new(gamma: JubJubExtended, delta: JubJubExtended) -> Self {
        Self { gamma, delta }
    }

    /// Getter for the gamma public key
    pub fn gamma(&self) -> &JubJubExtended {
        &self.gamma
    }

    /// Getter for the delta ciphertext
    pub fn delta(&self) -> &JubJubExtended {
        &self.delta
    }

    /// Uses assymetric encryption to return a cipher construction.
    ///
    /// The decryption will expect the secret of `public`.
    pub fn encrypt(
        secret: &JubJubScalar,
        public: &JubJubExtended,
        generator: &JubJubExtended,
        message: &JubJubExtended,
    ) -> Self {
        let gamma = generator * secret;
        let delta = message + public * secret;

        Self::new(gamma, delta)
    }

    /// Perform the decryption with the provided secret.
    pub fn decrypt(&self, secret: &JubJubScalar) -> JubJubExtended {
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

impl Mul<&JubJubScalar> for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn mul(self, rhs: &JubJubScalar) -> ElgamalCipher {
        ElgamalCipher::new(self.gamma * rhs, self.delta * rhs)
    }
}

impl Mul<JubJubScalar> for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn mul(self, rhs: JubJubScalar) -> ElgamalCipher {
        self * &rhs
    }
}

impl MulAssign<JubJubScalar> for ElgamalCipher {
    fn mul_assign(&mut self, rhs: JubJubScalar) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b JubJubScalar> for ElgamalCipher {
    fn mul_assign(&mut self, rhs: &'b JubJubScalar) {
        *self = &*self * rhs;
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use super::ElgamalCipher;
    use crate::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
    use dusk_bytes::Serializable;
    use rand_core::OsRng;

    fn gen() -> (JubJubScalar, JubJubExtended, JubJubScalar, JubJubExtended) {
        let a = JubJubScalar::random(&mut OsRng);
        let a_g = GENERATOR_EXTENDED * a;

        let b = JubJubScalar::random(&mut OsRng);
        let b_g = GENERATOR_EXTENDED * b;

        (a, a_g, b, b_g)
    }

    #[test]
    fn encrypt() {
        let (a, _, b, b_g) = gen();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);
        let decrypt = cipher.decrypt(&b);

        assert_eq!(m, decrypt);
    }

    #[test]
    fn wrong_key() {
        let (a, _, b, b_g) = gen();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);

        let wrong = b - JubJubScalar::one();
        let decrypt = cipher.decrypt(&wrong);

        assert_ne!(m, decrypt);
    }

    #[test]
    fn homomorphic_add() {
        let (a, _, b, b_g) = gen();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] + m[1] + m[2] + m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher = [ElgamalCipher::default(); 4];
        cipher.iter_mut().zip(m_g.iter()).for_each(|(x, y)| {
            *x = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, y)
        });

        let mut hom_cipher = cipher[0] + cipher[1];
        hom_cipher += cipher[2];
        hom_cipher = &hom_cipher + &cipher[3];

        let hom_decrypt = hom_cipher.decrypt(&b);

        assert_eq!(result, hom_decrypt);
    }

    #[test]
    fn homomorphic_sub() {
        let (a, _, b, b_g) = gen();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] - m[1] - m[2] - m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher = [ElgamalCipher::default(); 4];
        cipher.iter_mut().zip(m_g.iter()).for_each(|(x, y)| {
            *x = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, y)
        });

        let mut hom_cipher = cipher[0] - cipher[1];
        hom_cipher -= cipher[2];
        hom_cipher = &hom_cipher - &cipher[3];

        let hom_decrypt = hom_cipher.decrypt(&b);

        assert_eq!(result, hom_decrypt);
    }

    #[test]
    fn homomorphic_mul() {
        let (a, _, b, b_g) = gen();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] * m[1] * m[2] * m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher =
            ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m_g[0]);

        cipher = &cipher * &m[1];
        cipher = &cipher * m[2];
        cipher *= m[3];

        let decrypt = cipher.decrypt(&b);

        assert_eq!(result, decrypt);
    }

    #[test]
    fn to_bytes() {
        let (a, _, b, b_g) = gen();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);
        let cipher = cipher.to_bytes();
        let cipher = ElgamalCipher::from_bytes(&cipher).unwrap();

        let decrypt = cipher.decrypt(&b);

        assert_eq!(m, decrypt);
    }
}
