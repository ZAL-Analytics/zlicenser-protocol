use std::fs;

use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";

// network (0x02), storage (0x01), display (0x03): board-level, not plug-in peripherals
const INTERESTING_CLASSES: &[u32] = &[0x01, 0x02, 0x03];

/// Collects "vendor:device" PCI signatures, sorted by bus address for stable ordering.
pub fn pci_signatures() -> crate::Result<Vec<HardwareIdentifier>> {
    let mut entries: Vec<(String, Vec<u8>)> = fs::read_dir(PCI_DEVICES_PATH)
        .map_err(|e| Error::Collection(format!("{PCI_DEVICES_PATH}: {e}")))?
        .filter_map(|e| e.ok())
        .filter_map(|entry| {
            let addr = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();

            let class = read_hex_file(&path.join("class"))?;
            // PCI class is a 24-bit value; top byte is the base class.
            let base_class = (class >> 16) & 0xFF;
            if !INTERESTING_CLASSES.contains(&base_class) {
                return None;
            }

            let vendor = read_hex_file(&path.join("vendor"))?;
            let device = read_hex_file(&path.join("device"))?;
            let sig = format!("{vendor:04x}:{device:04x}");
            Some((addr, sig.into_bytes()))
        })
        .collect();

    if entries.is_empty() {
        return Err(Error::Collection("no interesting PCI devices found".into()));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(i, (_, sig))| {
            HardwareIdentifier::new(IdentifierKind::PciSignature { index: i as u8 }, sig)
        })
        .collect())
}

fn read_hex_file(path: &std::path::Path) -> Option<u32> {
    let raw = fs::read_to_string(path).ok()?;
    let s = raw.trim().trim_start_matches("0x");
    u32::from_str_radix(s, 16).ok()
}
