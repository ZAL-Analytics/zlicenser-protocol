use std::{fs, path::PathBuf};

use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

const NET_PATH: &str = "/sys/class/net";

// Interfaces to skip - these change too frequently to be useful identifiers.
const SKIP_PREFIXES: &[&str] = &[
    "lo", "veth", "docker", "br-", "virbr", "tun", "tap", "dummy",
];

/// Collects MAC addresses for physical interfaces, sorted by name for stable indexing.
pub fn mac_addresses() -> crate::Result<Vec<HardwareIdentifier>> {
    let mut entries: Vec<(String, Vec<u8>)> = fs::read_dir(NET_PATH)
        .map_err(|e| Error::Collection(format!("{NET_PATH}: {e}")))?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_PREFIXES.iter().any(|p| name.starts_with(p)) {
                return None;
            }
            let addr_path: PathBuf = [NET_PATH, &name, "address"].iter().collect();
            let addr = fs::read_to_string(&addr_path).ok()?;
            let trimmed = addr.trim();
            // Skip zero MACs (e.g. virtual interfaces that report 00:00:00:00:00:00)
            if trimmed == "00:00:00:00:00:00" || trimmed.is_empty() {
                return None;
            }
            Some((name, trimmed.as_bytes().to_vec()))
        })
        .collect();

    if entries.is_empty() {
        return Err(Error::Collection(
            "no physical network interfaces found".into(),
        ));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(i, (_, mac))| {
            HardwareIdentifier::new(IdentifierKind::MacAddress { index: i as u8 }, mac)
        })
        .collect())
}
