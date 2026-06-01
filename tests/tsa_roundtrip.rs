//! Integration tests for the TSA HTTP providers using an in-process mock server.
//!
//! Run with:
//!   cargo test --features tsa-test-utils -- tsa
//!
//! These tests exercise the full path:
//!   request_token_to() --> mock HTTP server --> TimeStampResp --> extract_token --> verify_with_extra_cert

#![cfg(feature = "tsa-test-utils")]

use reqwest::Client;
use sha2::{Digest, Sha256};
use zlicenser_protocol::tsa::{
    mock::MockTsaServer,
    providers::{freetsa, qtsa, sectigo},
    verify::{verify_with_extra_cert, TsaProvider},
};

const TEST_MESSAGE: &[u8] = b"test binding certificate bytes for round-trip";

#[tokio::test]
async fn freetsa_mock_roundtrip() {
    let server = MockTsaServer::start().await;
    let client = Client::new();

    let token = freetsa::request_token_to(&client, TEST_MESSAGE, &server.url())
        .await
        .expect("request_token_to failed");

    assert!(!token.is_empty(), "token should not be empty");

    let verified = verify_with_extra_cert(
        &token,
        TEST_MESSAGE,
        &server.test_cert.cert_der,
        TsaProvider::FreeTsa,
    )
    .expect("verify_with_extra_cert failed");

    let expected_hash = Sha256::digest(TEST_MESSAGE).to_vec();
    assert_eq!(
        verified.hashed_message, expected_hash,
        "message imprint should match TEST_MESSAGE hash"
    );
}

#[tokio::test]
async fn sectigo_mock_roundtrip() {
    let server = MockTsaServer::start().await;
    let client = Client::new();

    let token = sectigo::request_token_to(&client, TEST_MESSAGE, &server.url())
        .await
        .expect("request_token_to failed");

    assert!(!token.is_empty());

    let verified = verify_with_extra_cert(
        &token,
        TEST_MESSAGE,
        &server.test_cert.cert_der,
        TsaProvider::Sectigo,
    )
    .expect("verify_with_extra_cert failed");

    let expected_hash = Sha256::digest(TEST_MESSAGE).to_vec();
    assert_eq!(verified.hashed_message, expected_hash);
}

#[tokio::test]
async fn qtsa_mock_roundtrip() {
    let server = MockTsaServer::start().await;
    let client = Client::new();

    let token = qtsa::request_token_to(&client, TEST_MESSAGE, &server.url())
        .await
        .expect("request_token_to failed");

    assert!(!token.is_empty());

    let verified = verify_with_extra_cert(
        &token,
        TEST_MESSAGE,
        &server.test_cert.cert_der,
        TsaProvider::Qtsa,
    )
    .expect("verify_with_extra_cert failed");

    let expected_hash = Sha256::digest(TEST_MESSAGE).to_vec();
    assert_eq!(verified.hashed_message, expected_hash);
}

/// Confirms the mock server handles multiple simultaneous requests correctly.
#[tokio::test]
async fn mock_server_handles_concurrent_requests() {
    let server = MockTsaServer::start().await;
    let client = Client::new();
    let url = server.url();

    let handles: Vec<_> = (0u8..4)
        .map(|i| {
            let c = client.clone();
            let u = url.clone();
            let msg = vec![i; 32];
            tokio::spawn(async move { freetsa::request_token_to(&c, &msg, &u).await })
        })
        .collect();

    for h in handles {
        let token = h.await.expect("task panicked").expect("request failed");
        assert!(!token.is_empty());
    }
}

/// Directly tests the token builder without going through HTTP.
#[test]
fn build_token_for_hash_verifies_correctly() {
    use zlicenser_protocol::tsa::mock::{build_token_for_hash, TestCert};

    let cert = TestCert::generate();
    let message = b"direct token build test";
    let hash = Sha256::digest(message).to_vec();

    let token = build_token_for_hash(&hash, &cert.cert_der, &cert.key_der);

    let verified = verify_with_extra_cert(&token, message, &cert.cert_der, TsaProvider::FreeTsa)
        .expect("verification failed");

    assert_eq!(verified.hashed_message, hash);
}

/// Calls the real FreeTSA service. Only runs when ZLICENSER_LIVE_TSA=1 is set
/// so it never fires in CI accidentally.
#[tokio::test]
async fn freetsa_live_roundtrip() {
    if std::env::var("ZLICENSER_LIVE_TSA").as_deref() != Ok("1") {
        return;
    }
    let token = freetsa::request_token(&Client::new(), TEST_MESSAGE)
        .await
        .expect("live FreeTSA call failed");

    assert!(!token.is_empty());
    println!("Live FreeTSA token: {} bytes", token.len());
}
