// Field order is the wire format. Do not reorder without a protocol version bump.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub payload: ReceiptPayload,
    #[serde(with = "crate::wire::bytes::sig_bytes")]
    pub customer_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptPayload {
    pub protocol_version: u16,
    pub receipt_id: [u8; 16],
    pub grant_id: [u8; 16],
    pub request_id: [u8; 16],
    /// BLAKE3 hash of the full canonical LicenseGrant bytes (payload + vendor signature).
    pub grant_hash: [u8; 32],
    pub customer_public_key: [u8; 32],
    pub acknowledged_at: u64,
}
