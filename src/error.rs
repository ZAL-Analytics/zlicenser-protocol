#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("CBOR encode error: {0}")]
    Encode(String),

    #[error("CBOR decode error: {0}")]
    Decode(String),

    #[error("AEAD decryption failed")]
    Decrypt,

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("Shamir error: {0}")]
    Shamir(String),

    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u16, actual: u16 },

    #[error("malformed message: {0}")]
    Malformed(&'static str),
}
