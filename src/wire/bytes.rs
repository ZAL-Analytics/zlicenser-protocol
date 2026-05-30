// Serde helpers for fixed-size byte arrays that serde doesn't natively support (> 32 bytes).
// serialize_bytes / deserialize_bytes ensures CBOR major type 2 (byte string) wire encoding.

use serde::de::{Error, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

pub mod sig_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
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
