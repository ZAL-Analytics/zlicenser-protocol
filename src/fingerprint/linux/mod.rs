pub mod cpu;
pub mod dmi;
pub mod network;
pub mod pci;
pub mod storage;

#[cfg(feature = "tpm")]
pub mod tpm;

use crate::{
    error::Error,
    fingerprint::{
        extractor::HardwareCollector,
        identifier::{HardwareIdentifier, IdentifierTier},
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TierFilter {
    All,
    UnprivilegedOnly,
    PrivilegedOnly,
}

/// One identifier collection attempt with its result.
#[derive(Debug)]
pub struct CollectionAttempt {
    pub kind_hint: &'static str,
    pub tier: IdentifierTier,
    pub outcome: Result<HardwareIdentifier, String>,
}

impl CollectionAttempt {
    pub fn is_ok(&self) -> bool {
        self.outcome.is_ok()
    }

    fn ok(id: HardwareIdentifier) -> Self {
        let hint = id.kind.description();
        let tier = id.tier();
        Self {
            kind_hint: hint,
            tier,
            outcome: Ok(id),
        }
    }

    fn err(kind_hint: &'static str, tier: IdentifierTier, e: &crate::Error) -> Self {
        Self {
            kind_hint,
            tier,
            outcome: Err(e.to_string()),
        }
    }
}

/// Collects hardware identifiers from the local machine via sysfs and CPUID.
/// SMBIOS fields need `cap_dac_read_search` or root, grant it with:
/// `sudo setcap cap_dac_read_search+ep /path/to/your-binary`
pub struct LinuxCollector {
    pub min_identifiers: usize,
    tier_filter: TierFilter,
}

impl Default for LinuxCollector {
    fn default() -> Self {
        Self {
            min_identifiers: 4,
            tier_filter: TierFilter::All,
        }
    }
}

impl LinuxCollector {
    pub fn new(min_identifiers: usize) -> Self {
        Self {
            min_identifiers,
            tier_filter: TierFilter::All,
        }
    }

    /// Like default() but with a lower minimum, for when SMBIOS capability isn't guaranteed.
    pub fn best_effort() -> Self {
        Self {
            min_identifiers: 3,
            tier_filter: TierFilter::All,
        }
    }

    /// Medium/Low tier only, no SMBIOS or TPM, no root needed.
    pub fn unprivileged_only() -> Self {
        Self {
            min_identifiers: 3,
            tier_filter: TierFilter::UnprivilegedOnly,
        }
    }

    /// High-tier only (SMBIOS, TPM). Requires `cap_dac_read_search` or root.
    pub fn privileged_only() -> Self {
        Self {
            min_identifiers: 1,
            tier_filter: TierFilter::PrivilegedOnly,
        }
    }

    /// Like collect() but returns all attempts; never errors, caller decides if enough succeeded.
    pub fn collect_with_report(&self) -> Vec<CollectionAttempt> {
        let mut out = Vec::new();

        if self.tier_filter != TierFilter::UnprivilegedOnly {
            self.try_single(
                &mut out,
                "SMBIOS board UUID",
                IdentifierTier::High,
                dmi::board_uuid(),
            );
            self.try_single(
                &mut out,
                "SMBIOS system serial",
                IdentifierTier::High,
                dmi::system_serial(),
            );

            #[cfg(feature = "tpm")]
            self.try_single(
                &mut out,
                "TPM endorsement key",
                IdentifierTier::High,
                tpm::endorsement_key(),
            );
        }

        if self.tier_filter != TierFilter::PrivilegedOnly {
            self.try_single(
                &mut out,
                "CPU vendor + model",
                IdentifierTier::Medium,
                cpu::vendor_and_model(),
            );
            self.try_single(
                &mut out,
                "machine-id",
                IdentifierTier::Medium,
                dmi::machine_id(),
            );
            self.try_multi(
                &mut out,
                "disk serial",
                IdentifierTier::Medium,
                storage::disk_serials(),
            );
            self.try_multi(
                &mut out,
                "MAC address",
                IdentifierTier::Low,
                network::mac_addresses(),
            );
            self.try_multi(
                &mut out,
                "PCI device signature",
                IdentifierTier::Low,
                pci::pci_signatures(),
            );
        }

        out
    }

    #[allow(clippy::unused_self)]
    fn try_single(
        &self,
        out: &mut Vec<CollectionAttempt>,
        hint: &'static str,
        tier: IdentifierTier,
        result: crate::Result<HardwareIdentifier>,
    ) {
        out.push(match result {
            Ok(id) => CollectionAttempt::ok(id),
            Err(ref e) => CollectionAttempt::err(hint, tier, e),
        });
    }

    #[allow(clippy::unused_self)]
    fn try_multi(
        &self,
        out: &mut Vec<CollectionAttempt>,
        hint: &'static str,
        tier: IdentifierTier,
        result: crate::Result<Vec<HardwareIdentifier>>,
    ) {
        match result {
            Ok(ids) if ids.is_empty() => {
                out.push(CollectionAttempt::err(
                    hint,
                    tier,
                    &Error::Collection("none found".into()),
                ));
            }
            Ok(ids) => {
                for id in ids {
                    out.push(CollectionAttempt::ok(id));
                }
            }
            Err(ref e) => {
                out.push(CollectionAttempt::err(hint, tier, e));
            }
        }
    }
}

impl HardwareCollector for LinuxCollector {
    fn collect(&self) -> crate::Result<Vec<HardwareIdentifier>> {
        let attempts = self.collect_with_report();
        let ids: Vec<HardwareIdentifier> = attempts
            .into_iter()
            .filter_map(|a| a.outcome.ok())
            .collect();

        if ids.len() < self.min_identifiers {
            return Err(Error::Collection(format!(
                "only {collected} identifier(s) available, need at least {min}; \
                 try running with cap_dac_read_search if SMBIOS identifiers are missing",
                collected = ids.len(),
                min = self.min_identifiers,
            )));
        }

        Ok(ids)
    }
}
