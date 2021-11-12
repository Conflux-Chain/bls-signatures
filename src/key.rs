use std::io;

use ff::{PrimeField, PrimeFieldBits};
use group::Curve;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "pairing")]
use bls12_381::{hash_to_curve::HashToField, G1Affine, G1Projective, Scalar};
#[cfg(feature = "pairing")]
use hkdf::Hkdf;
use sha2::Sha256;
#[cfg(feature = "pairing")]
use sha2::{digest::generic_array::typenum::U48, digest::generic_array::GenericArray};

pub(crate) struct ScalarRepr(pub [u64; 4]);

#[cfg(feature = "blst")]
use blstrs::{G1Affine, G1Projective, G2Affine, Scalar};
#[cfg(feature = "blst")]
use group::prime::PrimeCurveAffine;

use crate::error::Error;
use crate::signature::*;

pub(crate) const G1_COMPRESSED_SIZE: usize = 48;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PublicKey(pub(crate) G1Projective);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PrivateKey(pub(crate) Scalar);

impl From<G1Projective> for PublicKey {
    fn from(val: G1Projective) -> Self {
        PublicKey(val)
    }
}

impl From<PublicKey> for G1Projective {
    fn from(val: PublicKey) -> Self {
        val.0
    }
}

impl From<Scalar> for PrivateKey {
    fn from(val: Scalar) -> Self {
        PrivateKey(val)
    }
}

impl From<PrivateKey> for Scalar {
    fn from(val: PrivateKey) -> Self {
        val.0
    }
}

impl From<PrivateKey> for ScalarRepr {
    fn from(val: PrivateKey) -> Self {
        ScalarRepr(val.0.to_le_bits().into_inner())
    }
}

impl<'a> From<&'a PrivateKey> for ScalarRepr {
    fn from(val: &'a PrivateKey) -> Self {
        (*val).into()
    }
}

pub trait Serialize: ::std::fmt::Debug + Sized {
    /// Writes the key to the given writer.
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()>;

    /// Recreate the key from bytes in the same form as `write_bytes` produced.
    fn from_bytes(raw: &[u8]) -> Result<Self, Error>;

    fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(8 * 4);
        self.write_bytes(&mut res).expect("preallocated");
        res
    }
}

impl PrivateKey {
    /// Generate a deterministic private key from the given bytes.
    ///
    /// They must be at least 32 bytes long to be secure, will panic otherwise.
    pub fn new<T: AsRef<[u8]>>(msg: T) -> Self {
        PrivateKey(key_gen(msg))
    }

    /// Generate a new private key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // IKM must be at least 32 bytes long:
        // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-2.3
        let mut ikm = [0u8; 32];
        rng.try_fill_bytes(&mut ikm)
            .expect("unable to produce secure randomness");

        Self::new(ikm)
    }

    /// Sign the given message.
    /// Calculated by `signature = hash_into_g2(message) * sk`
    #[cfg(feature = "pairing")]
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let mut p = hash(message.as_ref());
        p *= self.0;

        p.into()
    }

    /// Sign the given message.
    /// Calculated by `signature = hash_into_g2(message) * sk`
    #[cfg(feature = "blst")]
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let p = hash(message.as_ref());
        let mut sig = G2Affine::identity();

        unsafe {
            blst_lib::blst_sign_pk2_in_g1(
                std::ptr::null_mut(),
                sig.as_mut(),
                p.as_ref(),
                &self.0.into(),
            );
        }

        sig.into()
    }

    /// Get the public key for this private key.
    /// Calculated by `pk = g1 * sk`.
    #[cfg(feature = "pairing")]
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1Projective::generator();
        pk *= self.0;

        PublicKey(pk)
    }

    /// Get the public key for this private key.
    /// Calculated by `pk = g1 * sk`.
    #[cfg(feature = "blst")]
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1Affine::identity();

        unsafe {
            blst_lib::blst_sk_to_pk2_in_g1(std::ptr::null_mut(), pk.as_mut(), &self.0.into());
        }

        PublicKey(pk.into())
    }

    /// Deserializes a private key from the field element as a decimal number.
    pub fn from_string<T: AsRef<str>>(s: T) -> Result<Self, Error> {
        match Scalar::from_str_vartime(s.as_ref()) {
            Some(f) => Ok(f.into()),
            None => Err(Error::InvalidPrivateKey),
        }
    }
}

impl Serialize for PrivateKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        for digit in self.0.to_le_bits().as_buffer() {
            dest.write_all(&digit.to_le_bytes())?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        const FR_SIZE: usize = (Scalar::NUM_BITS as usize + 8 - 1) / 8;
        if raw.len() != FR_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; FR_SIZE];
        res.copy_from_slice(&raw[..FR_SIZE]);

        // TODO: once zero keys are rejected, insert check for zero.

        Scalar::from_repr_vartime(res)
            .map(Into::into)
            .ok_or(Error::InvalidPrivateKey)
    }
}

impl PublicKey {
    pub fn as_affine(&self) -> G1Affine {
        self.0.to_affine()
    }

    pub fn verify<T: AsRef<[u8]>>(&self, sig: Signature, message: T) -> bool {
        verify_messages(&sig, &[message.as_ref()], &[*self])
    }
}

impl Serialize for PublicKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        let t = self.0.to_affine();
        let tmp = t.to_compressed();
        dest.write_all(tmp.as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1_COMPRESSED_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; G1_COMPRESSED_SIZE];
        res.as_mut().copy_from_slice(raw);
        let affine: G1Affine =
            Option::from(G1Affine::from_compressed(&res)).ok_or(Error::GroupDecode)?;

        Ok(PublicKey(affine.into()))
    }
}

pub mod sigma_protocol {
    use super::{
        CryptoRng, Error, G1Projective, PrivateKey, PublicKey, RngCore, Scalar, Serialize, Sha256,
    };
    use cfg_if::cfg_if;
    use group::Group;
    use sha2::Digest;

    pub type Commit = G1Projective;
    pub type Answer = Scalar;

    pub fn decode_commit(bytes: &[u8]) -> Result<Commit, Error> {
        Ok(PublicKey::from_bytes(bytes)?.0)
    }

    pub fn decode_answer(bytes: &[u8]) -> Result<Answer, Error> {
        Ok(PrivateKey::from_bytes(bytes)?.0)
    }

    fn challenge(commit: G1Projective) -> Scalar {
        let mut serialized_commit: Vec<u8> = Vec::new();
        PublicKey(commit)
            .write_bytes(&mut serialized_commit)
            .expect("write bytes to vector should not fail");

        let mut sha256 = Sha256::default();
        sha256.update(&serialized_commit);

        let mut challenge_bytes = sha256.finalize();
        challenge_bytes[0] &= 0x3f;
        cfg_if! {
            if #[cfg(feature = "blst")] {
                // `from_bytes` read with little endian u64.
                Scalar::from_bytes_be(&challenge_bytes.into()).unwrap()
            } else if #[cfg(feature = "pairing")] {
                challenge_bytes.reverse();
                Scalar::from_bytes(&challenge_bytes.into()).unwrap()
            }
        }
    }

    pub fn verify(pubkey: PublicKey, commit: Commit, answer: Answer) -> bool {
        let challenge: Scalar = challenge(commit);

        let lhs = G1Projective::generator() * answer;

        let rhs = pubkey.0 * challenge + commit;

        lhs == rhs
    }

    pub fn prove<R: RngCore + CryptoRng>(prikey: PrivateKey, rng: &mut R) -> (Commit, Answer) {
        let random = PrivateKey::generate(rng);
        let commit = random.public_key().0;
        let challenge = challenge(commit);

        let answer = prikey.0 * challenge + random.0;
        (commit, answer)
    }

    #[cfg(test)]
    #[test]
    fn test_sigma_protocol() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        for i in 0..100 {
            let mut rng = StdRng::seed_from_u64(i);

            let prikey = PrivateKey::generate(&mut rng);
            let (commit, answer) = prove(prikey, &mut rng);
            assert!(verify(prikey.public_key(), commit, answer));
        }
    }
}

/// Generates a secret key as defined in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
#[cfg(feature = "pairing")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Scalar {
    // "BLS-SIG-KEYGEN-SALT-"
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

    let data = data.as_ref();
    assert!(data.len() >= 32, "IKM must be at least 32 bytes");

    // HKDF-Extract
    let mut msg = data.as_ref().to_vec();
    // append zero byte
    msg.push(0);
    let prk = Hkdf::<Sha256>::new(Some(SALT), &msg);

    // HKDF-Expand
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(prk.expand(&[0, 48], &mut result).is_ok());

    Scalar::from_okm(&result)
}

/// Generates a secret key as defined in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
#[cfg(feature = "blst")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Scalar {
    use std::convert::TryInto;

    let data = data.as_ref();
    assert!(data.len() >= 32, "IKM must be at least 32 bytes");

    let key_info = &[];
    let mut out = blst_lib::blst_scalar::default();
    unsafe {
        blst_lib::blst_keygen(
            &mut out,
            data.as_ptr(),
            data.len(),
            key_info.as_ptr(),
            key_info.len(),
        )
    };

    out.try_into().expect("invalid key generated")
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_bytes_roundtrip() {
        let rng = &mut ChaCha8Rng::seed_from_u64(12);
        let sk = PrivateKey::generate(rng);
        let sk_bytes = sk.as_bytes();

        assert_eq!(sk_bytes.len(), 32);
        assert_eq!(PrivateKey::from_bytes(&sk_bytes).unwrap(), sk);

        let pk = sk.public_key();
        let pk_bytes = pk.as_bytes();

        assert_eq!(pk_bytes.len(), 48);
        assert_eq!(PublicKey::from_bytes(&pk_bytes).unwrap(), pk);
    }

    #[test]
    fn test_key_gen() {
        let key_material = "hello world (it's a secret!) very secret stuff";
        let fr_val = key_gen(key_material);
        #[cfg(feature = "blst")]
        let expect = Scalar::from_u64s_le(&[
            0x8a223b0f9e257f7d,
            0x2d80f7b7f5ea6cc4,
            0xcc9e063a0ea0009c,
            0x4a73baed5cb75109,
        ])
        .unwrap();

        #[cfg(feature = "pairing")]
        let expect = Scalar::from_raw([
            0xa9f8187b89e6d49a,
            0xf870f34063ce4b16,
            0xc2aa3c1fff1bbaa3,
            0x60417787ee46e23f,
        ]);

        assert_eq!(fr_val, expect);
    }

    #[test]
    fn test_sig() {
        let msg = "this is the message";
        let sk = "this is the key and it is very secret";

        let sk = PrivateKey::new(sk);
        let sig = sk.sign(msg);
        let pk = sk.public_key();

        assert!(pk.verify(sig, msg));
    }
}
