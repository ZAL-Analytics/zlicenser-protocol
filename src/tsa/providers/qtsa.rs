//! QTSA qualified TSA provider. eIDAS qualified, statutory legal weight. Requires an API key.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

const URL: &str = "https://tsa.qtsa.eu/api/timestamp";

/// Sends message to QTSA and returns the raw DER token bytes.
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
        .header("Authorization", format!("Bearer {api_key}"))
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
