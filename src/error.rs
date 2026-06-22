#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("CBOR encode error: {0}")]
    Encode(String),

    #[error("CBOR decode error: {0}")]
    Decode(String),

    #[error("AEAD encryption failed")]
    Encrypt,

    #[error("AEAD decryption failed")]
    Decrypt,

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("Shamir error: {0}")]
    Shamir(String),

    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u16, actual: u16 },

    #[error("malformed message: {0}")]
    Malformed(Box<str>),

    // fingerprint errors
    #[error("hardware identifier collection failed: {0}")]
    Collection(String),

    #[error("fingerprint reconstruction failed: recovered {recovered} shares, need {threshold}")]
    InsufficientIdentifiers { recovered: usize, threshold: usize },

    // TSA errors
    #[error("TSA token parse error: {0}")]
    TsaParse(String),

    #[error("TSA token verification failed: {0}")]
    TsaVerification(String),

    #[error("TSA provider not in allowlist")]
    TsaUntrustedProvider,
}
