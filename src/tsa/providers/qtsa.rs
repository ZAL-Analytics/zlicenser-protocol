//! QTSA qualified TSA provider. eIDAS qualified, statutory legal weight.
//! Credentials are embedded in the endpoint URL.
//! Pass the URL from your application layer; do not read environment variables here.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

/// Sends `message` to the QTSA endpoint and returns the raw DER token bytes.
/// The URL may contain embedded credentials (`https://user:pass@tsa.qtsa.eu/api/timestamp`).
pub async fn request_token_to(
    client: &Client,
    message: &[u8],
    url: &str,
) -> crate::Result<Vec<u8>> {
    let req_der = super::ts_request::build(message);
    post(client, req_der, url).await
}

/// Like `request_token_to` but accepts a pre-computed SHA-256 digest instead of raw bytes.
/// Use this from the server layer where the digest has already been computed.
pub async fn request_token_hashed_to(
    client: &Client,
    hash: &[u8; 32],
    url: &str,
) -> crate::Result<Vec<u8>> {
    let req_der = super::ts_request::build_from_hash(hash);
    post(client, req_der, url).await
}

async fn post(client: &Client, req_der: Vec<u8>, url: &str) -> crate::Result<Vec<u8>> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .body(req_der)
        .send()
        .await
        .map_err(|e| Error::Collection(format!("QTSA request: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::TsaVerification(format!(
            "QTSA returned HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Collection(format!("QTSA response body: {e}")))?;

    super::ts_request::extract_token(&bytes)
}

pub fn provider() -> TsaProvider {
    TsaProvider::Qtsa
}
