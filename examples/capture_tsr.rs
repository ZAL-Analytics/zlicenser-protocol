//! Captures a real TimeStampResp (DER) from a TSA provider and saves it as a fixture.
//!
//! Run:
//!   cargo run --example capture_tsr --features tsa-clients -- --provider freetsa
//!   cargo run --example capture_tsr --features tsa-clients -- --provider sectigo
//!   QTSA_URL=<url-with-credentials> cargo run --example capture_tsr --features tsa-clients -- --provider qtsa
//!
//! Outputs are written to tests/fixtures/{provider}_sample.tsr.
//! FreeTSA and Sectigo are free with no quota. QTSA has a 50-request demo limit capture once
//! and commit; do not regenerate unnecessarily.

use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The stable message used for all fixture captures. Never change this existing fixtures
/// are only valid if re-verified against the same message.
const FIXTURE_MESSAGE: &[u8] = b"zlicenser tsa fixture v1";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let provider = args
        .windows(2)
        .find(|w| w[0] == "--provider")
        .map(|w| w[1].as_str())
        .unwrap_or_else(|| {
            eprintln!("Usage: capture_tsr --provider <freetsa|sectigo|qtsa>");
            std::process::exit(1);
        });

    let url = match provider {
        "freetsa" => "https://freetsa.org/tsr".to_string(),
        "sectigo" => "http://timestamp.sectigo.com".to_string(),
        "qtsa" => std::env::var("QTSA_URL").unwrap_or_else(|_| {
            eprintln!("QTSA_URL environment variable is not set");
            eprintln!("Set it to the full endpoint URL including embedded credentials.");
            std::process::exit(1);
        }),
        other => {
            eprintln!("Unknown provider: {other}. Must be one of: freetsa, sectigo, qtsa");
            std::process::exit(1);
        }
    };

    let expected_hash = Sha256::digest(FIXTURE_MESSAGE);
    println!("Provider:       {provider}");
    println!(
        "Message:        {:?}",
        std::str::from_utf8(FIXTURE_MESSAGE).unwrap()
    );
    println!("SHA-256 of msg: {}", hex::encode(expected_hash));
    println!("Sending request to {url} ...");

    let req_der = build_tsq(FIXTURE_MESSAGE);

    let client = reqwest::Client::new();
    let req = client
        .post(&url)
        .header("Content-Type", "application/timestamp-query")
        .body(req_der);

    let resp = req.send().await.unwrap_or_else(|e| {
        eprintln!("Request failed: {e}");
        std::process::exit(1);
    });

    if !resp.status().is_success() {
        eprintln!("Provider returned HTTP {}", resp.status());
        std::process::exit(1);
    }

    let raw_bytes = resp.bytes().await.unwrap_or_else(|e| {
        eprintln!("Failed to read response body: {e}");
        std::process::exit(1);
    });

    println!("Response:       {} bytes received", raw_bytes.len());

    // Write to tests/fixtures/ relative to the workspace root (where cargo is run from).
    let out_path = PathBuf::from(format!("tests/fixtures/{provider}_sample.tsr"));
    std::fs::create_dir_all(out_path.parent().unwrap()).unwrap_or_else(|e| {
        eprintln!("Could not create fixtures directory: {e}");
        std::process::exit(1);
    });
    std::fs::write(&out_path, &raw_bytes).unwrap_or_else(|e| {
        eprintln!("Could not write {}: {e}", out_path.display());
        std::process::exit(1);
    });

    println!("Saved to:       {}", out_path.display());
    println!("\nVerify the fixture looks valid with:");
    println!(
        "  openssl ts -reply -in {} -text 2>/dev/null | grep -E 'Status|Time stamp|TSA'",
        out_path.display()
    );
}

/// Builds a minimal DER-encoded TimeStampReq for SHA-256 of `message`.
fn build_tsq(message: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(message);

    let sha256_oid: &[u8] = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    let null: &[u8] = &[0x05, 0x00];
    let alg = sequence(&[sha256_oid, null].concat());
    let imprint = sequence(&[alg.as_slice(), &octet_string(hash.as_slice())].concat());

    let version: &[u8] = &[0x02, 0x01, 0x01];
    let cert_req: &[u8] = &[0x01, 0x01, 0xff];
    sequence(&[version, imprint.as_slice(), cert_req].concat())
}

fn sequence(inner: &[u8]) -> Vec<u8> {
    tlv(0x30, inner)
}

fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
    out.extend_from_slice(value);
    out
}
