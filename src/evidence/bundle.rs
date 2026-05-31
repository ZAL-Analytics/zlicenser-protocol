// Field order is the wire format. Do not reorder without a protocol version bump.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::signature::{Signature, SigningKey, VerifyingKey},
    wire,
};

/// Legally-admissible record of a completed license exchange.
/// Both sides hold a copy; neither can alter it without breaking both signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub payload: EvidenceBundlePayload,
    #[serde(with = "crate::wire::bytes::sig_bytes")]
    pub vendor_signature: [u8; 64],
    #[serde(with = "crate::wire::bytes::sig_bytes")]
    pub customer_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundlePayload {
    pub protocol_version: u16,
    pub bundle_id: [u8; 16],

    // all four protocol messages (raw CBOR bytes)
    pub license_request: Vec<u8>,
    pub license_grant: Vec<u8>,
    pub receipt: Vec<u8>,
    pub binding_certificate: Vec<u8>,

    // terms and consent
    /// hash of the exact terms text shown at purchase, vendor must produce the original to verify
    pub terms_hash: [u8; 32],
    pub consent: ConsentRecord,

    // payment and timestamp
    pub payment_reference: String,
    pub tsa_token: Vec<u8>,

    pub vendor_public_key: [u8; 32],
    pub customer_public_key: [u8; 32],
}

/// Customer consent captured at purchase time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub checkboxes_ticked: Vec<String>,
    pub consented_at: u64,
    pub ip_address: String,
}

impl EvidenceBundle {
    /// Canonical CBOR bytes of the payload, what both signatures are computed over.
    pub fn payload_bytes(payload: &EvidenceBundlePayload) -> crate::Result<Vec<u8>> {
        wire::encode(payload)
    }

    /// Vendor-signs the payload. Customer still needs to call `add_customer_signature`.
    pub fn sign_vendor(
        payload: EvidenceBundlePayload,
        vendor_key: &SigningKey,
    ) -> crate::Result<PartialBundle> {
        let payload_bytes = Self::payload_bytes(&payload)?;
        let sig = vendor_key.sign(&payload_bytes);
        Ok(PartialBundle {
            payload,
            vendor_signature: sig.to_bytes(),
        })
    }

    /// Verifies both signatures.
    pub fn verify(
        &self,
        vendor_vk: &VerifyingKey,
        customer_vk: &VerifyingKey,
    ) -> crate::Result<()> {
        let payload_bytes = Self::payload_bytes(&self.payload)?;
        vendor_vk.verify(
            &payload_bytes,
            &Signature::from_bytes(&self.vendor_signature),
        )?;
        customer_vk.verify(
            &payload_bytes,
            &Signature::from_bytes(&self.customer_signature),
        )?;
        Ok(())
    }

    /// Verifies only the vendor signature.
    pub fn verify_vendor(&self, vendor_vk: &VerifyingKey) -> crate::Result<()> {
        let payload_bytes = Self::payload_bytes(&self.payload)?;
        vendor_vk.verify(
            &payload_bytes,
            &Signature::from_bytes(&self.vendor_signature),
        )
    }

    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        wire::decode(bytes)
    }
}

/// Vendor-signed bundle awaiting the customer signature.
pub struct PartialBundle {
    pub payload: EvidenceBundlePayload,
    pub vendor_signature: [u8; 64],
}

impl PartialBundle {
    /// Adds the customer signature and completes the bundle.
    pub fn add_customer_signature(
        self,
        customer_key: &SigningKey,
    ) -> crate::Result<EvidenceBundle> {
        let payload_bytes = EvidenceBundle::payload_bytes(&self.payload)?;
        let sig = customer_key.sign(&payload_bytes);
        Ok(EvidenceBundle {
            payload: self.payload,
            vendor_signature: self.vendor_signature,
            customer_signature: sig.to_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::signature::SigningKey, error::Error, message::PROTOCOL_VERSION};

    fn fixture_payload() -> EvidenceBundlePayload {
        EvidenceBundlePayload {
            protocol_version: PROTOCOL_VERSION,
            bundle_id: [0x01; 16],
            license_request: vec![0x01, 0x02],
            license_grant: vec![0x03, 0x04],
            receipt: vec![0x05, 0x06],
            binding_certificate: vec![0x07, 0x08],
            terms_hash: [0xab; 32],
            consent: ConsentRecord {
                checkboxes_ticked: vec!["terms_of_service".into(), "privacy_policy".into()],
                consented_at: 1700000000,
                ip_address: "198.51.100.42".into(),
            },
            payment_reference: "ch_test_1234".into(),
            tsa_token: vec![0xde, 0xad, 0xbe, 0xef],
            vendor_public_key: [0xee; 32],
            customer_public_key: [0xcc; 32],
        }
    }

    #[test]
    fn roundtrip_serialization() {
        let vendor_sk = SigningKey::generate();
        let customer_sk = SigningKey::generate();

        let partial = EvidenceBundle::sign_vendor(fixture_payload(), &vendor_sk).unwrap();
        let bundle = partial.add_customer_signature(&customer_sk).unwrap();

        let bytes = bundle.to_bytes().unwrap();
        let decoded = EvidenceBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn verify_signatures_pass() {
        let vendor_sk = SigningKey::generate();
        let customer_sk = SigningKey::generate();

        let partial = EvidenceBundle::sign_vendor(fixture_payload(), &vendor_sk).unwrap();
        let bundle = partial.add_customer_signature(&customer_sk).unwrap();

        bundle
            .verify(&vendor_sk.verifying_key(), &customer_sk.verifying_key())
            .unwrap();
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let vendor_sk = SigningKey::generate();
        let customer_sk = SigningKey::generate();

        let partial = EvidenceBundle::sign_vendor(fixture_payload(), &vendor_sk).unwrap();
        let mut bundle = partial.add_customer_signature(&customer_sk).unwrap();

        // tamper after signing
        bundle.payload.payment_reference = "ch_tampered".into();

        let result = bundle.verify(&vendor_sk.verifying_key(), &customer_sk.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails_vendor_verification() {
        let vendor_sk = SigningKey::generate();
        let wrong_sk = SigningKey::generate();
        let customer_sk = SigningKey::generate();

        let partial = EvidenceBundle::sign_vendor(fixture_payload(), &vendor_sk).unwrap();
        let bundle = partial.add_customer_signature(&customer_sk).unwrap();

        let result = bundle.verify_vendor(&wrong_sk.verifying_key());
        assert!(matches!(result, Err(Error::SignatureInvalid)));
    }
}
