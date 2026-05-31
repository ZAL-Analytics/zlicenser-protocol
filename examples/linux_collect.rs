/// Collects real hardware identifiers from the current Linux machine and runs
/// a full enroll → reconstruct cycle, printing a detailed report.
///
/// Run (unprivileged, skips SMBIOS):
///   cargo run --example linux_collect --features collect-linux
///
/// Run (with SMBIOS, using setcap, preferred):
///   cargo build --example linux_collect --features collect-linux
///   sudo setcap cap_dac_read_search+ep target/debug/examples/linux_collect
///   ./target/debug/examples/linux_collect
///
/// Run (with SMBIOS + TPM, requires libtss2-dev and TPM 2.0 hardware):
///   cargo build --example linux_collect --features collect-linux,tpm
///   sudo setcap cap_dac_read_search+ep target/debug/examples/linux_collect
///   ./target/debug/examples/linux_collect
use zlicenser_protocol::fingerprint::{
    compute_commitment, FuzzyExtractor, IdentifierTier, LinuxCollector,
};

fn main() {
    let collector = LinuxCollector::best_effort();
    let report = collector.collect_with_report();

    println!("=== Hardware identifier collection report ===\n");
    println!("  {:<6}  {:<25}  {}", "TIER", "SOURCE", "RESULT");
    println!("  {}", "─".repeat(70));

    for attempt in &report {
        let tier_label = match attempt.tier {
            IdentifierTier::High => "HIGH  ",
            IdentifierTier::Medium => "MEDIUM",
            IdentifierTier::Low => "LOW   ",
        };
        match &attempt.outcome {
            Ok(id) => println!(
                "  {}  {:<25}  OK  {}",
                tier_label,
                attempt.kind_hint,
                display_value(&id.value),
            ),
            Err(reason) => println!(
                "  {}  {:<25}  SKIP  {}",
                tier_label, attempt.kind_hint, reason,
            ),
        }
    }

    let ids: Vec<_> = report.into_iter().filter_map(|a| a.outcome.ok()).collect();

    println!("\nCollected {} identifier(s)\n", ids.len());

    if ids.is_empty() {
        eprintln!("No identifiers collected, nothing to enroll.");
        std::process::exit(1);
    }

    let commitment = compute_commitment(&ids);
    println!("Fingerprint commitment  {}", hex::encode(commitment));

    let threshold = (ids.len() as u8).saturating_sub(2).max(1);
    println!("Enrolling with threshold {}/{}", threshold, ids.len());

    let (secret, record) = FuzzyExtractor::enroll(&ids, threshold).unwrap();
    println!(
        "Master secret (first 8 bytes)  {}\n",
        hex::encode(&secret.as_bytes()[..8])
    );

    match FuzzyExtractor::reconstruct(&ids, &record) {
        Ok(recovered) if recovered.as_bytes() == secret.as_bytes() => {
            println!("Reconstruction check   OK, record is valid for this machine");
        }
        Ok(_) => println!("Reconstruction check   MISMATCH, bug in enroll/reconstruct"),
        Err(e) => println!("Reconstruction check   FAIL, {e}"),
    }

    if ids.iter().all(|id| id.tier() != IdentifierTier::High) {
        println!(
            "\nNote: no High-tier identifiers collected (SMBIOS / TPM).\n\
             For stronger binding, grant cap_dac_read_search to your binary:\n\
             \n  sudo setcap cap_dac_read_search+ep <your-binary>\n"
        );
    }
}

/// Shows text identifiers as-is and binary ones (like TPM certs) as abbreviated hex.
fn display_value(value: &[u8]) -> String {
    let is_printable = value
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b':' || b == b'|');

    if is_printable {
        String::from_utf8_lossy(value).into_owned()
    } else if value.len() > 16 {
        // Binary blob (e.g. DER certificate), show size and a short hex prefix
        format!("[{} bytes]  {}…", value.len(), hex::encode(&value[..12]))
    } else {
        hex::encode(value)
    }
}
