/// Sends a message to FreeTSA (free, no credentials) and verifies the returned token.
///
/// Run:
///   cargo run --example tsa_stamp --features tsa-clients
///
/// FreeTSA is rate-limited; don't hammer it in CI. Gate this behind a
/// feature flag or manual test step in your own pipelines.
use reqwest::Client;
use zlicenser_protocol::tsa::{
    providers::freetsa,
    verify::{verify, TsaProvider},
};

#[tokio::main]
async fn main() {
    // This is the content you want timestamped , in production this would be
    // the CBOR bytes of the BindingCertificate.
    let message = b"example binding certificate bytes";

    println!("Requesting timestamp from FreeTSA...");
    println!("Message  {}", hex::encode(message));

    let client = Client::new();
    let token = match freetsa::request_token(&client, message).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    println!("Token    {} bytes received", token.len());
    println!(
        "Token hex (first 64 bytes)  {}",
        hex::encode(&token[..token.len().min(64)])
    );

    println!("\nVerifying token...");
    match verify(&token, message) {
        Ok(verified) => {
            let provider_label = match verified.provider {
                TsaProvider::FreeTsa => "FreeTSA (free tier)",
                TsaProvider::Sectigo => "Sectigo (standard tier)",
                TsaProvider::Qtsa => "QTSA (qualified tier)",
            };
            println!("  Provider   {}", provider_label);
            println!("  Serial     {}", verified.serial_number);
            println!("  Timestamp  {} (Unix)", verified.gen_time_unix);
            println!("  Hash match OK (message imprint verified)");
            println!("\nToken is valid.");
        }
        // Verification can fail if the embedded cert has been rotated by FreeTSA
        // since this binary was built. The token itself is still structurally valid.
        Err(e) => {
            println!("  Verification failed: {e}");
            println!(
                "\n  If this is a cert mismatch, the embedded FreeTSA cert in the\n\
                 binary may be outdated. Update src/tsa/certs/freetsa_*.der and rebuild."
            );
        }
    }
}
