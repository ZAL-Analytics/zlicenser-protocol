use raw_cpuid::CpuId;

use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

/// Combined vendor+brand string from CPUID, stable across reboots.
pub fn vendor_and_model() -> crate::Result<HardwareIdentifier> {
    let cpuid = CpuId::new();

    let vendor = cpuid
        .get_vendor_info()
        .map(|v| v.as_str().to_owned())
        .unwrap_or_else(|| "unknown-vendor".to_owned());

    let model = cpuid
        .get_processor_brand_string()
        .map(|b| b.as_str().trim().to_owned())
        .unwrap_or_else(|| "unknown-model".to_owned());

    if vendor == "unknown-vendor" && model == "unknown-model" {
        return Err(Error::Collection("CPUID returned no useful data".into()));
    }

    let combined = format!("{vendor}|{model}");
    Ok(HardwareIdentifier::new(
        IdentifierKind::CpuVendorAndModel,
        combined.into_bytes(),
    ))
}
