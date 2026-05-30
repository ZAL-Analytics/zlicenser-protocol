// Field order is the wire format. Do not reorder without a protocol version bump.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingCertificate {
    pub payload: BindingPayload,
    #[serde(with = "crate::wire::bytes::sig_bytes")]
    pub vendor_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingPayload {
    pub protocol_version: u16,
    pub binding_id: [u8; 16],
    pub grant_id: [u8; 16],
    pub receipt_id: [u8; 16],
    pub request_id: [u8; 16],
    /// BLAKE3 hash of the full canonical Receipt bytes (payload + customer signature).
    pub receipt_hash: [u8; 32],
    pub vendor_public_key: [u8; 32],
    pub bound_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<Vec<u8>>,
}
