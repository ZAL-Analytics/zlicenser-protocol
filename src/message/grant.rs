// Field order is the wire format. Do not reorder without a protocol version bump.

use serde::{Deserialize, Serialize};

use super::request::Identity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseGrant {
    pub payload: LicenseGrantPayload,
    #[serde(with = "crate::wire::bytes::sig_bytes")]
    pub vendor_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseGrantPayload {
    pub protocol_version: u16,
    pub grant_id: [u8; 16],
    pub request_id: [u8; 16],
    pub product_id: String,
    pub product_version: String,
    pub identity: Identity,
    pub fingerprint_commitment: [u8; 32],
    pub terms: LicenseTerms,
    pub vendor_public_key: [u8; 32],
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseTerms {
    pub connectivity: ConnectivityMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub max_seats: u32,
    /// Empty means no fingerprint restriction. Non-empty restricts to these specific hashes.
    pub allowed_fingerprints: Vec<[u8; 32]>,
    pub transfer_policy: TransferPolicy,
    pub tsa_tier: TsaTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectivityMode {
    AirGapped,
    Online,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferPolicy {
    VendorApproved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TsaTier {
    Free,
    Paid,
}
