// serde helpers for fixed-size byte arrays, keeps CBOR major type 2 (byte string) on the wire

/// 24-byte XChaCha20 nonces stored in enrollment records.
pub mod nonce_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8; 24], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = [u8; 24];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "exactly 24 bytes")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &"24"))
            }
        }
        d.deserialize_bytes(V)
    }
}

pub mod sig_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "exactly 64 bytes")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &"64"))
            }
        }
        d.deserialize_bytes(V)
    }
}
