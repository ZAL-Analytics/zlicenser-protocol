//! Evidency TSA provider. Commercially recognised, not eIDAS qualified. Requires an API key.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

const URL: &str = "https://tsa.evidency.io/api/timestamp";

/// Sends message to Evidency and returns the raw DER token bytes.
pub async fn request_token(
    client: &Client,
    message: &[u8],
    api_key: &str,
) -> crate::Result<Vec<u8>> {
    request_token_to(client, message, api_key, URL).await
}

/// Like `request_token` but with a configurable URL for tests against a local mock.
pub async fn request_token_to(
    client: &Client,
    message: &[u8],
    api_key: &str,
    url: &str,
) -> crate::Result<Vec<u8>> {
    let req_der = super::ts_request::build(message);

    let resp = client
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .header("X-API-Key", api_key)
        .body(req_der)
        .send()
        .await
        .map_err(|e| Error::Collection(format!("Evidency request: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::TsaVerification(format!(
            "Evidency returned HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Collection(format!("Evidency response body: {e}")))?;

    super::ts_request::extract_token(&bytes)
}

pub fn provider() -> TsaProvider {
    TsaProvider::Evidency
}
