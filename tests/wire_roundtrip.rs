use proptest::prelude::*;
use zlicenser_protocol::{
    message::{
        BindingCertificate, BindingPayload, ConnectivityMode, Identity, LicenseGrant,
        LicenseGrantPayload, LicenseRequest, LicenseTerms, Receipt, ReceiptPayload, TransferPolicy,
        TsaTier, PROTOCOL_VERSION,
    },
    wire,
};

prop_compose! {
    fn arb_identity()(
        name in "[a-zA-Z ]{1,64}",
        email in "[a-z]{1,32}@[a-z]{1,16}\\.[a-z]{2,4}",
        org in proptest::option::of("[a-zA-Z ]{1,64}"),
    ) -> Identity {
        Identity { name, email, organization: org }
    }
}

prop_compose! {
    fn arb_connectivity()(_dummy in 0u8..2) -> ConnectivityMode {
        if _dummy == 0 { ConnectivityMode::AirGapped } else { ConnectivityMode::Online }
    }
}

prop_compose! {
    fn arb_license_terms()(
        connectivity in arb_connectivity(),
        grace_period_seconds in proptest::option::of(any::<u64>()),
        expires_at in proptest::option::of(any::<u64>()),
        max_seats in any::<u32>(),
        fp_count in 0usize..4,
        fp_seed in any::<u8>(),
    ) -> LicenseTerms {
        LicenseTerms {
            connectivity,
            grace_period_seconds,
            expires_at,
            max_seats,
            allowed_fingerprints: (0..fp_count).map(|i| [fp_seed.wrapping_add(i as u8); 32]).collect(),
            transfer_policy: TransferPolicy::VendorApproved,
            tsa_tier: TsaTier::Free,
        }
    }
}

prop_compose! {
    fn arb_license_request()(
        request_id in any::<[u8; 16]>(),
        product_id in "[a-z-]{1,32}",
        product_version in "[0-9]{1,3}\\.[0-9]{1,3}",
        identity in arb_identity(),
        fingerprint_commitment in any::<[u8; 32]>(),
        customer_public_key in any::<[u8; 32]>(),
        timestamp in any::<u64>(),
    ) -> LicenseRequest {
        LicenseRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            product_id,
            product_version,
            identity,
            fingerprint_commitment,
            customer_public_key,
            timestamp,
        }
    }
}

prop_compose! {
    fn arb_license_grant()(
        grant_id in any::<[u8; 16]>(),
        request_id in any::<[u8; 16]>(),
        product_id in "[a-z-]{1,32}",
        product_version in "[0-9]{1,3}\\.[0-9]{1,3}",
        identity in arb_identity(),
        fingerprint_commitment in any::<[u8; 32]>(),
        terms in arb_license_terms(),
        vendor_public_key in any::<[u8; 32]>(),
        issued_at in any::<u64>(),
        vendor_signature in any::<[u8; 64]>(),
    ) -> LicenseGrant {
        LicenseGrant {
            payload: LicenseGrantPayload {
                protocol_version: PROTOCOL_VERSION,
                grant_id,
                request_id,
                product_id,
                product_version,
                identity,
                fingerprint_commitment,
                terms,
                vendor_public_key,
                issued_at,
                tsa_token: None,
            },
            vendor_signature,
        }
    }
}

prop_compose! {
    fn arb_receipt()(
        receipt_id in any::<[u8; 16]>(),
        grant_id in any::<[u8; 16]>(),
        request_id in any::<[u8; 16]>(),
        grant_hash in any::<[u8; 32]>(),
        customer_public_key in any::<[u8; 32]>(),
        acknowledged_at in any::<u64>(),
        customer_signature in any::<[u8; 64]>(),
    ) -> Receipt {
        Receipt {
            payload: ReceiptPayload {
                protocol_version: PROTOCOL_VERSION,
                receipt_id,
                grant_id,
                request_id,
                grant_hash,
                customer_public_key,
                acknowledged_at,
            },
            customer_signature,
        }
    }
}

prop_compose! {
    fn arb_binding()(
        binding_id in any::<[u8; 16]>(),
        grant_id in any::<[u8; 16]>(),
        receipt_id in any::<[u8; 16]>(),
        request_id in any::<[u8; 16]>(),
        receipt_hash in any::<[u8; 32]>(),
        vendor_public_key in any::<[u8; 32]>(),
        bound_at in any::<u64>(),
        vendor_signature in any::<[u8; 64]>(),
    ) -> BindingCertificate {
        BindingCertificate {
            payload: BindingPayload {
                protocol_version: PROTOCOL_VERSION,
                binding_id,
                grant_id,
                receipt_id,
                request_id,
                receipt_hash,
                vendor_public_key,
                bound_at,
                tsa_token: None,
            },
            vendor_signature,
        }
    }
}

proptest! {
    #[test]
    fn roundtrip_license_request(req in arb_license_request()) {
        let bytes = wire::encode(&req).unwrap();
        let decoded: LicenseRequest = wire::decode(&bytes).unwrap();
        prop_assert_eq!(req, decoded);
    }

    #[test]
    fn roundtrip_license_grant(grant in arb_license_grant()) {
        let bytes = wire::encode(&grant).unwrap();
        let decoded: LicenseGrant = wire::decode(&bytes).unwrap();
        prop_assert_eq!(grant, decoded);
    }

    #[test]
    fn roundtrip_receipt(receipt in arb_receipt()) {
        let bytes = wire::encode(&receipt).unwrap();
        let decoded: Receipt = wire::decode(&bytes).unwrap();
        prop_assert_eq!(receipt, decoded);
    }

    #[test]
    fn roundtrip_binding(binding in arb_binding()) {
        let bytes = wire::encode(&binding).unwrap();
        let decoded: BindingCertificate = wire::decode(&bytes).unwrap();
        prop_assert_eq!(binding, decoded);
    }
}
