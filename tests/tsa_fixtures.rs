//! Fixture-based tests that validate real provider responses against the full verify() path.
//!
//! These tests load captured `.tsr` files from tests/fixtures/ and run them through
//! `extract_token()` + `verify()` exercising the real embedded cert chain, not the
//! mock-server bypass path used in tsa_roundtrip.rs.
//!
//! Tests skip silently when fixtures are not present. To populate fixtures run:
//!   cargo run --example capture_tsr --features tsa-clients -- --provider freetsa
//!   cargo run --example capture_tsr --features tsa-clients -- --provider sectigo
//!   QTSA_URL=<url-with-credentials> cargo run --example capture_tsr --features tsa-clients -- --provider qtsa
//!
//! Once all three .tsr files are committed, these tests run as part of:
//!   cargo test --features tsa-clients

#![cfg(feature = "tsa-clients")]

use sha2::{Digest, Sha256};
use zlicenser_protocol::tsa::{
    providers::extract_token,
    verify::{verify, TsaProvider},
};

/// Must match the message used in capture_tsr.rs.
const FIXTURE_MESSAGE: &[u8] = b"zlicenser tsa fixture v1";

fn load_fixture(name: &str) -> Option<Vec<u8>> {
    std::fs::read(format!("tests/fixtures/{name}")).ok()
}

#[test]
fn freetsa_fixture_parses_and_verifies() {
    let Some(resp_bytes) = load_fixture("freetsa_sample.tsr") else {
        return;
    };

    let token = extract_token(&resp_bytes).expect("extract_token failed on freetsa fixture");
    let verified = verify(&token, FIXTURE_MESSAGE).expect("verify failed on freetsa fixture");

    assert_eq!(
        verified.hashed_message,
        Sha256::digest(FIXTURE_MESSAGE).to_vec(),
        "message imprint mismatch"
    );
    assert_eq!(verified.provider, TsaProvider::FreeTsa);
}

#[test]
fn sectigo_fixture_parses_and_verifies() {
    let Some(resp_bytes) = load_fixture("sectigo_sample.tsr") else {
        return;
    };

    let token = extract_token(&resp_bytes).expect("extract_token failed on sectigo fixture");
    let verified = verify(&token, FIXTURE_MESSAGE).expect("verify failed on sectigo fixture");

    assert_eq!(
        verified.hashed_message,
        Sha256::digest(FIXTURE_MESSAGE).to_vec(),
        "message imprint mismatch"
    );
    assert_eq!(verified.provider, TsaProvider::Sectigo);
}

#[test]
fn qtsa_fixture_parses_and_verifies() {
    let Some(resp_bytes) = load_fixture("qtsa_sample.tsr") else {
        return;
    };

    let token = extract_token(&resp_bytes).expect("extract_token failed on qtsa fixture");
    let verified = verify(&token, FIXTURE_MESSAGE).expect("verify failed on qtsa fixture");

    assert_eq!(
        verified.hashed_message,
        Sha256::digest(FIXTURE_MESSAGE).to_vec(),
        "message imprint mismatch"
    );
    assert_eq!(verified.provider, TsaProvider::Qtsa);
}
