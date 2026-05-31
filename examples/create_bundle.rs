/// Creates a realistic evidence bundle using real hardware identifiers and writes it to disk.
/// The four protocol messages are properly CBOR-encoded and signed.
///
/// Run (SMBIOS fields skipped without setcap):
///   cargo run --example create_bundle --features collect-linux -- --out test.bundle
///
/// Run (with SMBIOS via setcap, preferred):
///   cargo build --example create_bundle --features collect-linux
///   sudo setcap cap_dac_read_search+ep target/debug/examples/create_bundle
///   ./target/debug/examples/create_bundle --out test.bundle
///
/// Run (with SMBIOS + TPM, requires libtss2-dev and TPM 2.0 hardware):
///   cargo build --example create_bundle --features collect-linux,tpm
///   sudo setcap cap_dac_read_search+ep target/debug/examples/create_bundle
///   ./target/debug/examples/create_bundle --out test.bundle
///
/// Then inspect the result:
///   ./target/debug/zlicenser-bundle --read test.bundle
///   ./target/debug/zlicenser-bundle --verify test.bundle --vendor-key <printed below>
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zlicenser_protocol::{
    crypto::{hash, signature::SigningKey},
    evidence::{ConsentRecord, EvidenceBundle, EvidenceBundlePayload},
    fingerprint::{compute_commitment, IdentifierTier, LinuxCollector},
    message::{
        BindingCertificate, BindingPayload, ConnectivityMode, Identity, LicenseGrant,
        LicenseGrantPayload, LicenseRequest, LicenseTerms, Receipt, ReceiptPayload, TransferPolicy,
        TsaTier, PROTOCOL_VERSION,
    },
    wire,
};

fn main() {
    let out_path = parse_args();

    // Step 1: collect hardware identifiers ─────────────

    println!("Collecting hardware identifiers...\n");

    let collector = LinuxCollector::best_effort();
    let report = collector.collect_with_report();

    let mut high_ok = 0usize;
    let mut other_ok = 0usize;
    for a in &report {
        match &a.outcome {
            Ok(id) => {
                if a.tier == IdentifierTier::High {
                    high_ok += 1;
                } else {
                    other_ok += 1;
                }
                println!(
                    "  [OK  ] {:?}  {}  =  {}",
                    a.tier,
                    a.kind_hint,
                    display_value(&id.value)
                );
            }
            Err(reason) => println!("  [SKIP] {:?}  {} , {}", a.tier, a.kind_hint, reason),
        }
    }

    let ids: Vec<_> = report.into_iter().filter_map(|a| a.outcome.ok()).collect();
    if ids.is_empty() {
        eprintln!("\nNo identifiers collected, cannot continue.");
        std::process::exit(1);
    }
    println!(
        "\nCollected {} identifier(s)  ({} high-tier, {} medium/low)\n",
        ids.len(),
        high_ok,
        other_ok
    );

    if high_ok == 0 {
        println!(
            "  Tip: SMBIOS fields were skipped (permission denied).\n  \
             For stronger hardware binding, grant the capability once:\n\n  \
             sudo setcap cap_dac_read_search+ep target/debug/examples/create_bundle\n  \
             ./target/debug/examples/create_bundle --out {}\n",
            out_path.display()
        );
    }

    let commitment = compute_commitment(&ids);

    // Step 2: generate keypairs (in production these come from your key store)

    let vendor_sk = SigningKey::generate();
    let customer_sk = SigningKey::generate();
    let now = unix_now();

    // Step 3: build and sign the four protocol messages

    // LicenseRequest  (customer → vendor)
    let request_id = derive_id(b"request", now);
    let grant_id = derive_id(b"grant", now);
    let receipt_id = derive_id(b"receipt", now);
    let binding_id = derive_id(b"binding", now);

    let identity = Identity {
        name: "Example Customer".into(),
        email: "customer@example.com".into(),
        organization: Some("Example Corp Ltd".into()),
    };

    let request = LicenseRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        product_id: "example-product".into(),
        product_version: "1.0.0".into(),
        identity: identity.clone(),
        fingerprint_commitment: commitment,
        customer_public_key: customer_sk.verifying_key().to_bytes(),
        timestamp: now,
    };
    let request_bytes = wire::encode(&request).unwrap();

    // LicenseGrant  (vendor → customer), vendor signs the payload
    let one_year = 365 * 24 * 3600;
    let grant_payload = LicenseGrantPayload {
        protocol_version: PROTOCOL_VERSION,
        grant_id,
        request_id,
        product_id: "example-product".into(),
        product_version: "1.0.0".into(),
        identity: identity.clone(),
        fingerprint_commitment: commitment,
        terms: LicenseTerms {
            connectivity: ConnectivityMode::Online,
            grace_period_seconds: Some(86400),
            expires_at: Some(now + one_year),
            max_seats: 1,
            allowed_fingerprints: vec![commitment],
            transfer_policy: TransferPolicy::VendorApproved,
            tsa_tier: TsaTier::Free,
        },
        vendor_public_key: vendor_sk.verifying_key().to_bytes(),
        issued_at: now,
        tsa_token: None,
    };
    let grant_payload_bytes = wire::encode(&grant_payload).unwrap();
    let grant = LicenseGrant {
        payload: grant_payload,
        vendor_signature: vendor_sk.sign(&grant_payload_bytes).to_bytes(),
    };
    let grant_bytes = wire::encode(&grant).unwrap();

    // Receipt  (customer → vendor), customer signs the payload
    let receipt_payload = ReceiptPayload {
        protocol_version: PROTOCOL_VERSION,
        receipt_id,
        grant_id,
        request_id,
        grant_hash: *hash::hash(&grant_bytes).as_bytes(),
        customer_public_key: customer_sk.verifying_key().to_bytes(),
        acknowledged_at: now,
    };
    let receipt_payload_bytes = wire::encode(&receipt_payload).unwrap();
    let receipt = Receipt {
        payload: receipt_payload,
        customer_signature: customer_sk.sign(&receipt_payload_bytes).to_bytes(),
    };
    let receipt_bytes = wire::encode(&receipt).unwrap();

    // BindingCertificate  (vendor → customer), vendor signs the payload
    let binding_payload = BindingPayload {
        protocol_version: PROTOCOL_VERSION,
        binding_id,
        grant_id,
        receipt_id,
        request_id,
        receipt_hash: *hash::hash(&receipt_bytes).as_bytes(),
        vendor_public_key: vendor_sk.verifying_key().to_bytes(),
        bound_at: now,
        tsa_token: None,
    };
    let binding_payload_bytes = wire::encode(&binding_payload).unwrap();
    let binding = BindingCertificate {
        payload: binding_payload,
        vendor_signature: vendor_sk.sign(&binding_payload_bytes).to_bytes(),
    };
    let binding_bytes = wire::encode(&binding).unwrap();

    // Step 4: assemble and dual-sign the evidence bundle ───────────────────

    let terms_text =
        b"Example product license terms - replace with real terms text at purchase time.";
    let terms_hash = *hash::hash(terms_text).as_bytes();

    let bundle_payload = EvidenceBundlePayload {
        protocol_version: PROTOCOL_VERSION,
        bundle_id: derive_id(b"bundle", now),
        license_request: request_bytes,
        license_grant: grant_bytes,
        receipt: receipt_bytes,
        binding_certificate: binding_bytes,
        terms_hash,
        consent: ConsentRecord {
            checkboxes_ticked: vec!["terms_of_service".into(), "privacy_policy".into()],
            consented_at: now,
            ip_address: "198.51.100.1".into(),
        },
        payment_reference: "ch_example_3RkX1234ABCD".into(),
        tsa_token: vec![], // attach a real RFC 3161 token here in production
        vendor_public_key: vendor_sk.verifying_key().to_bytes(),
        customer_public_key: customer_sk.verifying_key().to_bytes(),
    };

    let partial = EvidenceBundle::sign_vendor(bundle_payload, &vendor_sk).unwrap();
    let bundle = partial.add_customer_signature(&customer_sk).unwrap();

    // Step 5: write to disk ────────

    let bundle_bytes = bundle.to_bytes().unwrap();
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    std::fs::write(&out_path, &bundle_bytes).unwrap();

    // Summary ──

    println!("Bundle written to  {}", out_path.display());
    println!("Size               {} bytes", bundle_bytes.len());
    println!("Commitment         {}", hex::encode(commitment));
    println!(
        "Vendor key         {}",
        hex::encode(vendor_sk.verifying_key().to_bytes())
    );
    println!(
        "Customer key       {}",
        hex::encode(customer_sk.verifying_key().to_bytes())
    );
    println!();
    println!("Read it:");
    println!(
        "  ./target/debug/zlicenser-bundle --read {}",
        out_path.display()
    );
    println!();
    println!("Verify it:");
    println!(
        "  ./target/debug/zlicenser-bundle --verify {} --vendor-key {}",
        out_path.display(),
        hex::encode(vendor_sk.verifying_key().to_bytes()),
    );
}

// helpers ──────

/// Shows text identifiers as-is and binary ones (like TPM certs) as abbreviated hex.
fn display_value(value: &[u8]) -> String {
    let is_printable = value
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b':' || b == b'|');

    if is_printable {
        String::from_utf8_lossy(value).into_owned()
    } else if value.len() > 16 {
        format!("[{} bytes]  {}…", value.len(), hex::encode(&value[..12]))
    } else {
        hex::encode(value)
    }
}

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let pos = args.iter().position(|a| a == "--out");
    match pos.and_then(|i| args.get(i + 1)) {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!(
                "Usage: cargo run --example create_bundle --features collect-linux -- --out <path>"
            );
            std::process::exit(1);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

/// Derives a deterministic 16-byte ID from a label + timestamp so the IDs are
/// unique per run but don't require a random number generator in the example.
fn derive_id(label: &[u8], ts: u64) -> [u8; 16] {
    let mut input = label.to_vec();
    input.extend_from_slice(&ts.to_le_bytes());
    let h = *hash::hash(&input).as_bytes();
    h[..16].try_into().unwrap()
}
