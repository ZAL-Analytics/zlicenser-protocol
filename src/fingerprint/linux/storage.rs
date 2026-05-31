use std::{fs, path::PathBuf};

use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

const BLOCK_PATH: &str = "/sys/block";

// Partition devices and loop/ram/zram devices aren't useful identifiers.
const SKIP_PREFIXES: &[&str] = &["loop", "ram", "zram", "dm-", "md"];

/// Collects disk serial numbers from sysfs, sorted by device name for stable indexing.
pub fn disk_serials() -> crate::Result<Vec<HardwareIdentifier>> {
    let mut results: Vec<(String, Vec<u8>)> = fs::read_dir(BLOCK_PATH)
        .map_err(|e| Error::Collection(format!("{BLOCK_PATH}: {e}")))?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIP_PREFIXES.iter().any(|p| name.starts_with(p)) {
                return None;
            }
            // Try the standard sysfs serial path first, then the NVMe variant.
            let serial = read_block_serial(&name)?;
            Some((name, serial))
        })
        .collect();

    if results.is_empty() {
        return Err(Error::Collection("no disk serial numbers found".into()));
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(results
        .into_iter()
        .enumerate()
        .map(|(i, (_, serial))| {
            HardwareIdentifier::new(IdentifierKind::DiskSerial { index: i as u8 }, serial)
        })
        .collect())
}

fn read_block_serial(device: &str) -> Option<Vec<u8>> {
    // Classic SATA/SAS devices
    let sata_path: PathBuf = [BLOCK_PATH, device, "device", "serial"].iter().collect();
    // NVMe devices expose serial under a slightly different path
    let nvme_path: PathBuf = [BLOCK_PATH, device, "device", "device", "serial"]
        .iter()
        .collect();

    for path in [&sata_path, &nvme_path] {
        if let Ok(serial) = fs::read_to_string(path) {
            let s = serial.trim();
            if !s.is_empty() && s != "unknown" {
                return Some(s.as_bytes().to_vec());
            }
        }
    }
    None
}
