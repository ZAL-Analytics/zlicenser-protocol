use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(chacha20poly1305::Key);

impl AeadKey {
    pub fn generate() -> Self {
        let mut bytes = chacha20poly1305::Key::default();
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(*chacha20poly1305::Key::from_slice(b))
    }
}

impl PartialEq for AeadKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; 24]);

impl Nonce {
    pub fn random() -> Self {
        let mut b = [0u8; 24];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(b: [u8; 24]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

/// Encrypts `plaintext` with XChaCha20-Poly1305. Returns ciphertext with appended 16-byte tag.
/// The nonce is not prepended; callers carry it separately in their wire structs.
pub fn encrypt(key: &AeadKey, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key.0);
    let xnonce = XNonce::from_slice(&nonce.0);
    cipher
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .expect("XChaCha20Poly1305 encrypt: key or nonce size mismatch, this is a bug")
}

pub fn decrypt(
    key: &AeadKey,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(&key.0);
    let xnonce = XNonce::from_slice(&nonce.0);
    cipher
        .decrypt(xnonce, Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // XChaCha20-Poly1305 test vector from draft-irtf-cfrg-xchacha-03 §A.3
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3
    #[test]
    fn xchacha20poly1305_test_vector() {
        let key_bytes: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce_bytes: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: &[u8] = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        // Expected ciphertext+tag (130 bytes = 114 plaintext + 16 tag) from the draft
        let expected_ct: &[u8] = &[
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e, 0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8,
            0x78, 0x0a, 0xcf, 0x49,
        ];

        let key = AeadKey::from_bytes(&key_bytes);
        let nonce = Nonce::from_bytes(nonce_bytes);
        let ct = encrypt(&key, &nonce, plaintext, aad);
        assert_eq!(ct.as_slice(), expected_ct);

        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampered_tag_returns_decrypt_error() {
        let key = AeadKey::generate();
        let nonce = Nonce::random();
        let mut ct = encrypt(&key, &nonce, b"secret", b"");
        // Flip last byte of the Poly1305 tag
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(matches!(decrypt(&key, &nonce, &ct, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn wrong_aad_returns_decrypt_error() {
        let key = AeadKey::generate();
        let nonce = Nonce::random();
        let ct = encrypt(&key, &nonce, b"msg", b"right-aad");
        assert!(matches!(decrypt(&key, &nonce, &ct, b"wrong-aad"), Err(Error::Decrypt)));
    }
}
