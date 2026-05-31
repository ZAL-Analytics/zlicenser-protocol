use hkdf::Hkdf;
use sha2::Sha256;

pub const INFO_PAYLOAD_KEY: &[u8] = b"zlicenser-v1-payload-key";
pub const INFO_FINGERPRINT_KEY: &[u8] = b"zlicenser-v1-fingerprint-key";

/// HKDF-SHA-256 into `out`. Panics if out exceeds 255*32 bytes.
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out)
        .expect("HKDF output length exceeds 255 * HashLen");
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Appendix A.1, Test Case 1 (HMAC-SHA-256)
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let mut out = [0u8; 42];
        derive(&ikm, &salt, &info, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn domain_constants_are_distinct() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive(b"ikm", b"salt", INFO_PAYLOAD_KEY, &mut a);
        derive(b"ikm", b"salt", INFO_FINGERPRINT_KEY, &mut b);
        assert_ne!(a, b);
    }
}
