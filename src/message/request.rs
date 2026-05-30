// Field order is the wire format. Do not reorder without a protocol version bump.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseRequest {
    pub protocol_version: u16,
    pub request_id: [u8; 16],
    pub product_id: String,
    pub product_version: String,
    pub identity: Identity,
    pub fingerprint_commitment: [u8; 32],
    pub customer_public_key: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}
