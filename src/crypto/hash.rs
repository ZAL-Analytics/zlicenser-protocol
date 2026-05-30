use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

pub fn hash(input: &[u8]) -> Hash {
    Hash(*blake3::hash(input).as_bytes())
}

pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash {
    Hash(*blake3::keyed_hash(key, input).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // BLAKE3 reference test vectors, input filled with counter bytes 0x00, 0x01, ...
    // Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json

    #[test]
    fn blake3_empty() {
        let h = hash(&[]);
        assert_eq!(
            h.as_bytes(),
            &[
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36,
                0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a,
                0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
            ]
        );
    }

    #[test]
    fn blake3_one_zero_byte() {
        let h = hash(&[0x00]);
        assert_eq!(
            h.as_bytes(),
            &[
                0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1, 0x4c, 0x88, 0x6e, 0x35, 0xaf,
                0xa0, 0x36, 0x73, 0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1, 0x51, 0x02,
                0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13
            ]
        );
    }

    #[test]
    fn blake3_single_byte_0x61() {
        // RFC-style sanity: "a" = 0x61
        let expected = blake3::hash(b"a");
        let h = hash(b"a");
        assert_eq!(h.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn blake3_deterministic() {
        assert_eq!(hash(b"hello"), hash(b"hello"));
        assert_ne!(hash(b"hello"), hash(b"world"));
    }

    #[test]
    fn keyed_hash_differs_from_unkeyed() {
        let key = [0xaau8; 32];
        let h = keyed_hash(&key, b"test");
        let u = hash(b"test");
        assert_ne!(h.as_bytes(), u.as_bytes());
    }

    #[test]
    fn keyed_hash_key_sensitive() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        assert_ne!(keyed_hash(&k1, b"data"), keyed_hash(&k2, b"data"));
    }
}
