use zlicenser_protocol::{
    message::{
        BindingCertificate, BindingPayload, ConnectivityMode, Identity, LicenseGrant,
        LicenseGrantPayload, LicenseRequest, LicenseTerms, Receipt, ReceiptPayload,
        TransferPolicy, TsaTier,
    },
    wire,
};

fn fixture_identity() -> Identity {
    Identity {
        name: "Alice Example".to_string(),
        email: "alice@example.com".to_string(),
        organization: None,
    }
}

fn fixture_identity_with_org() -> Identity {
    Identity {
        name: "Bob Corp".to_string(),
        email: "bob@corp.example".to_string(),
        organization: Some("Corp Example Ltd".to_string()),
    }
}

fn fixture_license_terms() -> LicenseTerms {
    LicenseTerms {
        connectivity: ConnectivityMode::Online,
        grace_period_seconds: Some(86400),
        expires_at: Some(1893456000),
        max_seats: 1,
        allowed_fingerprints: vec![[0xcd; 32]],
        transfer_policy: TransferPolicy::VendorApproved,
        tsa_tier: TsaTier::Free,
    }
}

fn fixture_license_request() -> LicenseRequest {
    LicenseRequest {
        protocol_version: 1,
        request_id: [0x01; 16],
        product_id: "my-product".to_string(),
        product_version: "1.0.0".to_string(),
        identity: fixture_identity(),
        fingerprint_commitment: [0xab; 32],
        customer_public_key: [0xee; 32],
        timestamp: 1700000000,
    }
}

fn fixture_license_grant() -> LicenseGrant {
    LicenseGrant {
        payload: LicenseGrantPayload {
            protocol_version: 1,
            grant_id: [0x01; 16],
            request_id: [0x02; 16],
            product_id: "my-product".to_string(),
            product_version: "1.0.0".to_string(),
            identity: fixture_identity(),
            fingerprint_commitment: [0xab; 32],
            terms: fixture_license_terms(),
            vendor_public_key: [0xee; 32],
            issued_at: 1700000000,
            tsa_token: None,
        },
        vendor_signature: [0xff; 64],
    }
}

fn fixture_receipt() -> Receipt {
    Receipt {
        payload: ReceiptPayload {
            protocol_version: 1,
            receipt_id: [0x03; 16],
            grant_id: [0x01; 16],
            request_id: [0x02; 16],
            grant_hash: [0xba; 32],
            customer_public_key: [0xcc; 32],
            acknowledged_at: 1700000100,
        },
        customer_signature: [0xaa; 64],
    }
}

fn fixture_binding() -> BindingCertificate {
    BindingCertificate {
        payload: BindingPayload {
            protocol_version: 1,
            binding_id: [0x04; 16],
            grant_id: [0x01; 16],
            receipt_id: [0x03; 16],
            request_id: [0x02; 16],
            receipt_hash: [0xdc; 32],
            vendor_public_key: [0xee; 32],
            bound_at: 1700000200,
            tsa_token: None,
        },
        vendor_signature: [0xff; 64],
    }
}

#[test]
fn snapshot_identity_wire() {
    let id = fixture_identity();
    let bytes = wire::encode(&id).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_identity_with_org_wire() {
    let id = fixture_identity_with_org();
    let bytes = wire::encode(&id).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_license_terms_wire() {
    let terms = fixture_license_terms();
    let bytes = wire::encode(&terms).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_connectivity_mode_wire() {
    let online = wire::encode(&ConnectivityMode::Online).unwrap();
    let air_gapped = wire::encode(&ConnectivityMode::AirGapped).unwrap();
    insta::assert_snapshot!("online", hex::encode(&online));
    insta::assert_snapshot!("air_gapped", hex::encode(&air_gapped));
}

#[test]
fn snapshot_license_request_wire() {
    let req = fixture_license_request();
    let bytes = wire::encode(&req).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_license_grant_wire() {
    let grant = fixture_license_grant();
    let bytes = wire::encode(&grant).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_receipt_wire() {
    let receipt = fixture_receipt();
    let bytes = wire::encode(&receipt).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}

#[test]
fn snapshot_binding_wire() {
    let binding = fixture_binding();
    let bytes = wire::encode(&binding).unwrap();
    insta::assert_snapshot!(hex::encode(&bytes));
}
