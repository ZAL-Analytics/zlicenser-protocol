//! QTSA qualified TSA provider. eIDAS qualified, statutory legal weight.
//! Credentials are embedded in the endpoint URL. Set QTSA_URL at runtime.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

/// Sends message to QTSA and returns the raw DER token bytes.
/// Reads the endpoint (with embedded credentials) from the `QTSA_URL` environment variable.
pub async fn request_token(client: &Client, message: &[u8]) -> crate::Result<Vec<u8>> {
    let url = std::env::var("QTSA_URL")
        .map_err(|_| Error::Collection("QTSA_URL environment variable is not set".into()))?;
    request_token_to(client, message, &url).await
}

/// Like `request_token` but with a configurable URL for tests against a local mock.
/// The URL may contain embedded credentials (e.g. `https://user:pass@tsa.qtsa.eu/api/timestamp`).
pub async fn request_token_to(
    client: &Client,
    message: &[u8],
    url: &str,
) -> crate::Result<Vec<u8>> {
    let req_der = super::ts_request::build(message);

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
