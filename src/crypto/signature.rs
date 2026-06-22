use ed25519_dalek::{Signer, Verifier};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

// raw seed bytes so we can derive Zeroize, dalek's SigningKey doesn't impl it
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(ed25519_dalek::SigningKey::from_bytes(&self.0).verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(ed25519_dalek::SigningKey::from_bytes(&self.0).sign(msg))
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, Error> {
        ed25519_dalek::VerifyingKey::from_bytes(b)
            .map(Self)
            .map_err(|_| Error::Malformed("invalid Ed25519 verifying key".into()))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        self.0
            .verify(msg, &sig.0)
            .map_err(|_| Error::SignatureInvalid)
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for VerifyingKey {}

#[derive(Debug, Clone)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(b))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes().ct_eq(&other.0.to_bytes()).into()
    }
}

impl Eq for Signature {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 chapter 6.1 Test Vector 1, Ed25519 with empty message
    #[test]
    fn rfc8032_test_vector_1() {
        let private_bytes: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected_pub: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected_sig: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let sk = SigningKey::from_bytes(&private_bytes);
        assert_eq!(sk.verifying_key().to_bytes(), expected_pub);
        let sig = sk.sign(b"");
        assert_eq!(sig.to_bytes(), expected_sig);
        sk.verifying_key().verify(b"", &sig).unwrap();
    }

    #[test]
    fn bit_flipped_signature_fails() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let mut sig_bytes = sk.sign(b"message").to_bytes();
        sig_bytes[0] ^= 0x01;
        let bad_sig = Signature::from_bytes(&sig_bytes);
        assert!(matches!(
            vk.verify(b"message", &bad_sig),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate();
        let msg = b"roundtrip test";
        let sig = sk.sign(msg);
        sk.verifying_key().verify(msg, &sig).unwrap();
    }
}
