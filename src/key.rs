use std::io::{self, Cursor, Read};

use ff::PrimeField;
use groupy::{CurveAffine, CurveProjective, EncodedPoint};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "pairing")]
use hkdf::Hkdf;
#[cfg(feature = "pairing")]
use paired::bls12_381::{Fr, FrRepr, G1Affine, G1Compressed, G1};
#[cfg(feature = "pairing")]
use paired::BaseFromRO;
#[cfg(feature = "pairing")]
use sha2::{digest::generic_array::typenum::U48, digest::generic_array::GenericArray, Sha256};

#[cfg(feature = "blst")]
use blstrs::{
    G1Affine, G1Compressed, G1Projective as G1, G2Affine, Scalar as Fr, ScalarRepr as FrRepr,
};

use crate::error::Error;
use crate::signature::*;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PublicKey(pub(crate) G1);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PrivateKey(pub(crate) Fr);

impl From<G1> for PublicKey {
    fn from(val: G1) -> Self {
        PublicKey(val)
    }
}

impl From<PublicKey> for G1 {
    fn from(val: PublicKey) -> Self {
        val.0
    }
}

impl From<Fr> for PrivateKey {
    fn from(val: Fr) -> Self {
        PrivateKey(val)
    }
}

impl From<PrivateKey> for Fr {
    fn from(val: PrivateKey) -> Self {
        val.0
    }
}

impl From<PrivateKey> for FrRepr {
    fn from(val: PrivateKey) -> Self {
        val.0.into_repr()
    }
}

impl<'a> From<&'a PrivateKey> for FrRepr {
    fn from(val: &'a PrivateKey) -> Self {
        val.0.into_repr()
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
        p.mul_assign(self.0);

        p.into()
    }

    /// Sign the given message.
    /// Calculated by `signature = hash_into_g2(message) * sk`
    #[cfg(feature = "blst")]
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let p = hash(message.as_ref());
        let mut sig = G2Affine::zero();

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
        let mut pk = G1::one();
        pk.mul_assign(self.0);

        PublicKey(pk)
    }

    /// Get the public key for this private key.
    /// Calculated by `pk = g1 * sk`.
    #[cfg(feature = "blst")]
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1Affine::zero();

        unsafe {
            blst_lib::blst_sk_to_pk2_in_g1(std::ptr::null_mut(), pk.as_mut(), &self.0.into());
        }

        PublicKey(pk.into_projective())
    }

    /// Deserializes a private key from the field element as a decimal number.
    pub fn from_string<T: AsRef<str>>(s: T) -> Result<Self, Error> {
        match Fr::from_str(s.as_ref()) {
            Some(f) => Ok(f.into()),
            None => Err(Error::InvalidPrivateKey),
        }
    }
}

impl Serialize for PrivateKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        for digit in self.0.into_repr().as_ref().iter() {
            dest.write_all(&digit.to_le_bytes())?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        const FR_SIZE: usize = (Fr::NUM_BITS as usize + 8 - 1) / 8;
        if raw.len() != FR_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = FrRepr::default();
        let mut reader = Cursor::new(raw);
        let mut buf = [0; 8];

        for digit in res.0.as_mut().iter_mut() {
            reader.read_exact(&mut buf)?;
            *digit = u64::from_le_bytes(buf);
        }

        // TODO: once zero keys are rejected, insert check for zero.

        Ok(Fr::from_repr(res)?.into())
    }
}

impl PublicKey {
    pub fn as_affine(&self) -> G1Affine {
        self.0.into_affine()
    }

    pub fn verify<T: AsRef<[u8]>>(&self, sig: Signature, message: T) -> bool {
        verify_messages(&sig, &[message.as_ref()], &[*self])
    }
}

impl Serialize for PublicKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        let t = self.0.into_affine();
        let tmp = G1Compressed::from_affine(t);
        dest.write_all(tmp.as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1Compressed::size() {
            return Err(Error::SizeMismatch);
        }

        let mut res = G1Compressed::empty();
        res.as_mut().copy_from_slice(raw);
        let affine = res.into_affine()?;

        Ok(PublicKey(affine.into_projective()))
    }
}

pub mod sigma_protocol {
    use super::{
        CryptoRng, CurveProjective, Error, Fr, PrivateKey, PublicKey, RngCore, Serialize, Sha256,
        G1,
    };
    use ff::Field;
    use sha2::Digest;

    pub type Commit = G1;
    pub type Answer = Fr;

    pub fn decode_commit(bytes: &[u8]) -> Result<Commit, Error> {
        Ok(PublicKey::from_bytes(bytes)?.0)
    }

    pub fn decode_answer(bytes: &[u8]) -> Result<Answer, Error> {
        Ok(PrivateKey::from_bytes(bytes)?.0)
    }

    fn challenge(commit: G1) -> Fr {
        let mut serialized_commit: Vec<u8> = Vec::new();
        PublicKey(commit)
            .write_bytes(&mut serialized_commit)
            .expect("write bytes to vector should not fail");

        let mut sha256 = Sha256::default();
        sha256.update(&serialized_commit);

        let mut challenge_bytes = sha256.finalize().as_slice().to_vec();
        challenge_bytes[31] = 0;
        challenge_bytes[30] = 0;
        PrivateKey::from_bytes(&challenge_bytes)
            .expect("length should be always match")
            .0
    }

    pub fn verify(pubkey: PublicKey, commit: Commit, answer: Answer) -> bool {
        let challenge: Fr = challenge(commit);

        let mut lhs = G1::one();
        lhs.mul_assign(answer);

        let mut rhs = pubkey.0;
        rhs.mul_assign(challenge);
        rhs.add_assign(&commit);

        lhs == rhs
    }

    pub fn prove<R: RngCore + CryptoRng>(prikey: PrivateKey, rng: &mut R) -> (Commit, Answer) {
        let random = PrivateKey::generate(rng);
        let commit = random.public_key().0;
        let challenge = challenge(commit);

        let mut answer = prikey.0;
        answer.mul_assign(&challenge);
        answer.add_assign(&random.0);
        (commit, answer)
    }

    #[cfg(test)]
    #[test]
    fn test_sigma_protocol() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(73);

        let prikey = PrivateKey::generate(&mut rng);
        let (commit, answer) = prove(prikey, &mut rng);
        assert!(verify(prikey.public_key(), commit, answer));
    }
}

/// Generates a secret key as defined in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
#[cfg(feature = "pairing")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Fr {
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

    Fr::from_okm(&result)
}

/// Generates a secret key as defined in
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
#[cfg(feature = "blst")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Fr {
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
        let expect = FrRepr([
            0x8a223b0f9e257f7d,
            0x2d80f7b7f5ea6cc4,
            0xcc9e063a0ea0009c,
            0x4a73baed5cb75109,
        ]);

        #[cfg(feature = "pairing")]
        let expect = FrRepr([
            0xa9f8187b89e6d49a,
            0xf870f34063ce4b16,
            0xc2aa3c1fff1bbaa3,
            0x60417787ee46e23f,
        ]);

        assert_eq!(fr_val, Fr::from_repr(expect).unwrap());
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
