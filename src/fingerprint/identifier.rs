use serde::{Deserialize, Serialize};

/// How stable and privileged an identifier is. Higher tier = more trusted, slower to change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentifierTier {
    /// SMBIOS data, TPM endorsement key. Requires root to read during enrollment.
    High,
    /// CPU model, machine-id, disk serials. Readable without root, stable across minor changes.
    Medium,
    /// MAC addresses, PCI device IDs. Can change (NIC swap, PCIe card added).
    Low,
}

/// Which hardware component a value came from. Indexed variants are ordered by sysfs path for stability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentifierKind {
    // High tier
    SmbiosBoardUuid,
    SmbiosSystemSerial,
    TpmEndorsementKey,
    // Medium tier
    CpuVendorAndModel,
    MachineId,
    DiskSerial { index: u8 },
    // Low tier
    MacAddress { index: u8 },
    PciSignature { index: u8 },
}

impl IdentifierKind {
    pub fn description(&self) -> &'static str {
        match self {
            IdentifierKind::SmbiosBoardUuid => "SMBIOS board UUID",
            IdentifierKind::SmbiosSystemSerial => "SMBIOS system serial",
            IdentifierKind::TpmEndorsementKey => "TPM endorsement key",
            IdentifierKind::CpuVendorAndModel => "CPU vendor + model",
            IdentifierKind::MachineId => "machine-id",
            IdentifierKind::DiskSerial { .. } => "disk serial",
            IdentifierKind::MacAddress { .. } => "MAC address",
            IdentifierKind::PciSignature { .. } => "PCI device signature",
        }
    }

    pub fn tier(&self) -> IdentifierTier {
        match self {
            IdentifierKind::SmbiosBoardUuid
            | IdentifierKind::SmbiosSystemSerial
            | IdentifierKind::TpmEndorsementKey => IdentifierTier::High,

            IdentifierKind::CpuVendorAndModel
            | IdentifierKind::MachineId
            | IdentifierKind::DiskSerial { .. } => IdentifierTier::Medium,

            IdentifierKind::MacAddress { .. } | IdentifierKind::PciSignature { .. } => {
                IdentifierTier::Low
            }
        }
    }
}

/// One hardware identifier read from the local machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIdentifier {
    pub kind: IdentifierKind,
    /// Raw bytes of the identifier before hashing.
    pub value: Vec<u8>,
}

impl HardwareIdentifier {
    pub fn new(kind: IdentifierKind, value: Vec<u8>) -> Self {
        Self { kind, value }
    }

    pub fn tier(&self) -> IdentifierTier {
        self.kind.tier()
    }
}
