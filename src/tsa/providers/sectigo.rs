//! Sectigo TSA provider. Standard tier, commercially recognised. Free, no credentials required.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

const URL: &str = "http://timestamp.sectigo.com";

/// Sends `message` to Sectigo and returns the raw DER timestamp token bytes.
pub async fn request_token(client: &Client, message: &[u8]) -> crate::Result<Vec<u8>> {
    request_token_to(client, message, URL).await
}

/// Like `request_token` but with a configurable URL for tests against a local mock.
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
        .map_err(|e| Error::Collection(format!("Sectigo request: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::TsaVerification(format!(
            "Sectigo returned HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Collection(format!("Sectigo response body: {e}")))?;

    super::ts_request::extract_token(&bytes)
}

pub fn provider() -> TsaProvider {
    TsaProvider::Sectigo
}
