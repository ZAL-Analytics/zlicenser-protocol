//! FreeTSA.org provider, free tier, tamper evidence only.

use reqwest::Client;

use crate::{error::Error, tsa::TsaProvider};

const URL: &str = "https://freetsa.org/tsr";

/// Sends `message` to FreeTSA and returns the raw DER timestamp token bytes.
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
        .map_err(|e| Error::Collection(format!("FreeTSA request: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::TsaVerification(format!(
            "FreeTSA returned HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Collection(format!("FreeTSA response body: {e}")))?;

    super::ts_request::extract_token(&bytes)
}

pub fn provider() -> TsaProvider {
    TsaProvider::FreeTsa
}
