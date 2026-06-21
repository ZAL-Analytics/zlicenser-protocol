use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use zlicenser_protocol::{crypto::signature::VerifyingKey, evidence::EvidenceBundle};

/// Inspect and verify zlicenser evidence bundles.
///
/// Examples:
///   zlicenser-bundle --read    license.bundle
///   zlicenser-bundle --verify  license.bundle
///   zlicenser-bundle --verify  license.bundle --vendor-key aabbccdd...
#[derive(Parser)]
#[command(name = "zlicenser-bundle", version, about, long_about = None)]
struct Cli {
    /// Pretty-print all fields of an evidence bundle
    #[arg(long, value_name = "FILE", group = "action")]
    read: Option<PathBuf>,

    /// Verify signatures on an evidence bundle
    #[arg(long, value_name = "FILE", group = "action")]
    verify: Option<PathBuf>,

    /// Assert that the vendor public key embedded in the bundle matches this
    /// 64-character hex string (32 bytes). Optional but recommended in scripts.
    #[arg(long, value_name = "HEX", requires = "action")]
    vendor_key: Option<String>,

    /// Assert that the customer public key embedded in the bundle matches this
    /// 64-character hex string (32 bytes). Optional.
    #[arg(long, value_name = "HEX", requires = "action")]
    customer_key: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let result = if let Some(path) = cli.read {
        cmd_read(&path)
    } else if let Some(path) = cli.verify {
        cmd_verify(
            &path,
            cli.vendor_key.as_deref(),
            cli.customer_key.as_deref(),
        )
    } else {
        // clap's group = "action" makes one required, but handle it anyway
        eprintln!("Use --read or --verify. Try --help.");
        std::process::exit(1);
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

// read command

fn cmd_read(path: &PathBuf) -> Result<()> {
    let bundle = load_bundle(path)?;
    let p = &bundle.payload;

    println!("Evidence Bundle");
    println!("{}", "=".repeat(60));
    println!();

    field("Protocol version", &p.protocol_version.to_string());
    field("Bundle ID", &hex::encode(p.bundle_id));
    println!();

    section("Protocol Messages");
    field(
        "  license_request",
        &format!("{} bytes", p.license_request.len()),
    );
    field(
        "  license_grant",
        &format!("{} bytes", p.license_grant.len()),
    );
    field("  receipt", &format!("{} bytes", p.receipt.len()));
    field(
        "  binding_certificate",
        &format!("{} bytes", p.binding_certificate.len()),
    );
    println!();

    section("Terms");
    field("  terms_hash", &hex::encode(p.terms_hash));
    println!();

    section("Consent");
    field("  checkboxes", &p.consent.checkboxes_ticked.join(", "));
    field("  consented_at", &format_unix(p.consent.consented_at));
    field("  ip_address", &p.consent.ip_address);
    println!();

    section("Payment");
    field("  reference", &p.payment_reference);
    println!();

    section("Timestamp");
    if p.tsa_token.is_empty() {
        field("  tsa_token", "not present");
    } else {
        field("  tsa_token", &format!("{} bytes", p.tsa_token.len()));
    }
    println!();

    section("Public Keys");
    field("  vendor", &hex::encode(p.vendor_public_key));
    field("  customer", &hex::encode(p.customer_public_key));
    println!();

    section("Signatures");
    field("  vendor", &format_sig(&bundle.vendor_signature));
    field("  customer", &format_sig(&bundle.customer_signature));

    Ok(())
}

// verify command

fn cmd_verify(
    path: &PathBuf,
    expected_vendor_hex: Option<&str>,
    expected_customer_hex: Option<&str>,
) -> Result<()> {
    println!("Reading bundle from '{}'", path.display());
    let bundle = load_bundle(path)?;

    // Decode the public keys that are embedded in the bundle.
    let vendor_vk = VerifyingKey::from_bytes(&bundle.payload.vendor_public_key)
        .context("vendor public key in bundle is not a valid Ed25519 key")?;
    let customer_vk = VerifyingKey::from_bytes(&bundle.payload.customer_public_key)
        .context("customer public key in bundle is not a valid Ed25519 key")?;

    println!();
    println!(
        "  vendor key   {}",
        hex::encode(bundle.payload.vendor_public_key)
    );
    println!(
        "  customer key {}",
        hex::encode(bundle.payload.customer_public_key)
    );
    println!();

    // Verify both Ed25519 signatures.
    print!("  vendor signature   ");
    match bundle.verify_vendor(&vendor_vk) {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL  ({e})");
            println!("\nVerification failed.");
            std::process::exit(1);
        }
    }

    print!("  customer signature ");
    match bundle.verify(&vendor_vk, &customer_vk) {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL  ({e})");
            println!("\nVerification failed.");
            std::process::exit(1);
        }
    }

    // Optional: assert the embedded keys match caller-provided expected values.
    if let Some(hex) = expected_vendor_hex {
        let expected = parse_key_hex(hex, "vendor")?;
        if expected != bundle.payload.vendor_public_key {
            println!();
            println!("  expected vendor key mismatch");
            println!("    expected  {}", hex::encode(expected));
            println!(
                "    got       {}",
                hex::encode(bundle.payload.vendor_public_key)
            );
            bail!("vendor key does not match --vendor-key");
        }
        println!("  expected vendor key  OK");
    }

    if let Some(hex) = expected_customer_hex {
        let expected = parse_key_hex(hex, "customer")?;
        if expected != bundle.payload.customer_public_key {
            println!();
            println!("  expected customer key mismatch");
            bail!("customer key does not match --customer-key");
        }
        println!("  expected customer key  OK");
    }

    println!();
    println!("Bundle integrity verified.");
    Ok(())
}

// helpers

fn load_bundle(path: &PathBuf) -> Result<EvidenceBundle> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read '{}'", path.display()))?;
    EvidenceBundle::from_bytes(&bytes)
        .with_context(|| format!("'{}' is not a valid evidence bundle", path.display()))
}

fn parse_key_hex(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).with_context(|| format!("--{label}-key is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("--{label}-key must be exactly 32 bytes (64 hex chars)"))
}

fn format_unix(ts: u64) -> String {
    match DateTime::from_timestamp(ts as i64, 0) {
        Some(dt) => {
            let dt: DateTime<Utc> = dt;
            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        }
        None => format!("{ts} (invalid timestamp)"),
    }
}

fn format_sig(sig: &[u8; 64]) -> String {
    // Split the 128-char hex across two lines for readability.
    let hex = hex::encode(sig);
    format!("{}\n{:>25}{}", &hex[..64], "", &hex[64..])
}

fn field(label: &str, value: &str) {
    println!("  {label:<22} {value}");
}

fn section(title: &str) {
    println!("{title}");
}
