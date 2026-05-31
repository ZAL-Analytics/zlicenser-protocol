use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

// Linux exposes SMBIOS data under this sysfs directory.
const DMI_ID_PATH: &str = "/sys/class/dmi/id";
const MACHINE_ID_PATH: &str = "/etc/machine-id";

/// SMBIOS board UUID. Usually readable without root.
pub fn board_uuid() -> crate::Result<HardwareIdentifier> {
    let raw = read_dmi_file("board_serial").or_else(|_| read_dmi_file("product_uuid"))?;
    Ok(HardwareIdentifier::new(
        IdentifierKind::SmbiosBoardUuid,
        raw,
    ))
}

/// SMBIOS product serial number. May require root on some hardware.
pub fn system_serial() -> crate::Result<HardwareIdentifier> {
    let raw = read_dmi_file("product_serial")?;
    Ok(HardwareIdentifier::new(
        IdentifierKind::SmbiosSystemSerial,
        raw,
    ))
}

/// /etc/machine-id, stable across reboots, no root needed.
pub fn machine_id() -> crate::Result<HardwareIdentifier> {
    let raw = std::fs::read_to_string(MACHINE_ID_PATH)
        .map_err(|e| Error::Collection(format!("machine-id: {e}")))?;
    Ok(HardwareIdentifier::new(
        IdentifierKind::MachineId,
        raw.trim().as_bytes().to_vec(),
    ))
}

fn read_dmi_file(name: &str) -> crate::Result<Vec<u8>> {
    let path = format!("{DMI_ID_PATH}/{name}");
    let content =
        std::fs::read_to_string(&path).map_err(|e| Error::Collection(format!("{path}: {e}")))?;
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "Unknown" || trimmed == "Not Specified" {
        return Err(Error::Collection(format!("{path}: value not available")));
    }
    Ok(trimmed.as_bytes().to_vec())
}
