use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarrantyDeclaration {
    None,
    Days30,
    Days90,
    Year1,
    Year2,
}

impl fmt::Display for WarrantyDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Days30 => "Days30",
            Self::Days90 => "Days90",
            Self::Year1 => "Year1",
            Self::Year2 => "Year2",
        })
    }
}

impl FromStr for WarrantyDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "Days30" => Ok(Self::Days30),
            "Days90" => Ok(Self::Days90),
            "Year1" => Ok(Self::Year1),
            "Year2" => Ok(Self::Year2),
            _ => Err(crate::Error::Malformed(
                "unknown WarrantyDeclaration".into(),
            )),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundDeclaration {
    None,
    EuStatutory14Day,
    Days30,
}

impl fmt::Display for RefundDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::EuStatutory14Day => "EuStatutory14Day",
            Self::Days30 => "Days30",
        })
    }
}

impl FromStr for RefundDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "EuStatutory14Day" => Ok(Self::EuStatutory14Day),
            "Days30" => Ok(Self::Days30),
            _ => Err(crate::Error::Malformed("unknown RefundDeclaration".into())),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationDeclaration {
    NotPossible,
    WithNotice7Day,
    Immediate,
}

impl fmt::Display for RevocationDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotPossible => "NotPossible",
            Self::WithNotice7Day => "WithNotice7Day",
            Self::Immediate => "Immediate",
        })
    }
}

impl FromStr for RevocationDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NotPossible" => Ok(Self::NotPossible),
            "WithNotice7Day" => Ok(Self::WithNotice7Day),
            "Immediate" => Ok(Self::Immediate),
            _ => Err(crate::Error::Malformed(
                "unknown RevocationDeclaration".into(),
            )),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryDeclaration {
    Perpetual,
    TimeLimitedMonths(u32),
}

impl fmt::Display for ExpiryDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Perpetual => f.write_str("Perpetual"),
            Self::TimeLimitedMonths(n) => write!(f, "TimeLimitedMonths({n})"),
        }
    }
}

impl FromStr for ExpiryDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "Perpetual" {
            return Ok(Self::Perpetual);
        }
        if let Some(inner) = s
            .strip_prefix("TimeLimitedMonths(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let n = inner
                .parse::<u32>()
                .map_err(|_| crate::Error::Malformed("invalid TimeLimitedMonths payload".into()))?;
            return Ok(Self::TimeLimitedMonths(n));
        }
        Err(crate::Error::Malformed("unknown ExpiryDeclaration".into()))
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportScope {
    BugsOnly,
    Installation,
    FullTechnical,
    Unlimited,
}

impl fmt::Display for SupportScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BugsOnly => "BugsOnly",
            Self::Installation => "Installation",
            Self::FullTechnical => "FullTechnical",
            Self::Unlimited => "Unlimited",
        })
    }
}

impl FromStr for SupportScope {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BugsOnly" => Ok(Self::BugsOnly),
            "Installation" => Ok(Self::Installation),
            "FullTechnical" => Ok(Self::FullTechnical),
            "Unlimited" => Ok(Self::Unlimited),
            _ => Err(crate::Error::Malformed("unknown SupportScope".into())),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatesPolicy {
    None,
    IncludedMonths(u32),
    Perpetual,
}

impl fmt::Display for UpdatesPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::IncludedMonths(n) => write!(f, "IncludedMonths({n})"),
            Self::Perpetual => f.write_str("Perpetual"),
        }
    }
}

impl FromStr for UpdatesPolicy {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "None" {
            return Ok(Self::None);
        }
        if s == "Perpetual" {
            return Ok(Self::Perpetual);
        }
        if let Some(inner) = s
            .strip_prefix("IncludedMonths(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let n = inner
                .parse::<u32>()
                .map_err(|_| crate::Error::Malformed("invalid IncludedMonths payload".into()))?;
            return Ok(Self::IncludedMonths(n));
        }
        Err(crate::Error::Malformed("unknown UpdatesPolicy".into()))
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityDeclaration {
    AirGapped,
    Online,
    AlwaysOnline,
}

impl fmt::Display for ConnectivityDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AirGapped => "AirGapped",
            Self::Online => "Online",
            Self::AlwaysOnline => "AlwaysOnline",
        })
    }
}

impl FromStr for ConnectivityDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AirGapped" => Ok(Self::AirGapped),
            "Online" => Ok(Self::Online),
            "AlwaysOnline" => Ok(Self::AlwaysOnline),
            _ => Err(crate::Error::Malformed(
                "unknown ConnectivityDeclaration".into(),
            )),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDeclaration {
    NotAvailable,
    VendorApproval,
}

impl fmt::Display for TransferDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAvailable => "NotAvailable",
            Self::VendorApproval => "VendorApproval",
        })
    }
}

impl FromStr for TransferDeclaration {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NotAvailable" => Ok(Self::NotAvailable),
            "VendorApproval" => Ok(Self::VendorApproval),
            _ => Err(crate::Error::Malformed(
                "unknown TransferDeclaration".into(),
            )),
        }
    }
}

/// All term declarations for a product. Passed by value to template generation and validation.
///
/// This type is not serialized; it crosses the server/protocol boundary via function call only.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermDeclarations {
    pub warranty: WarrantyDeclaration,
    pub refund: RefundDeclaration,
    pub revocation: RevocationDeclaration,
    pub expiry: ExpiryDeclaration,
    pub support_available: bool,
    pub support_scope: Option<SupportScope>,
    pub updates_policy: UpdatesPolicy,
    pub connectivity: ConnectivityDeclaration,
    pub transfer: TransferDeclaration,
}

impl TermDeclarations {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        warranty: WarrantyDeclaration,
        refund: RefundDeclaration,
        revocation: RevocationDeclaration,
        expiry: ExpiryDeclaration,
        support_available: bool,
        support_scope: Option<SupportScope>,
        updates_policy: UpdatesPolicy,
        connectivity: ConnectivityDeclaration,
        transfer: TransferDeclaration,
    ) -> Self {
        Self {
            warranty,
            refund,
            revocation,
            expiry,
            support_available,
            support_scope,
            updates_policy,
            connectivity,
            transfer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Valid,
    Warnings,
    Conflicts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Warning,
    Conflict,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsFinding {
    pub severity: FindingSeverity,
    pub declaration_key: String,
    pub declared_value: String,
    /// Truncated to 512 bytes.
    pub conflicting_excerpt: String,
    pub reason: String,
    pub auto_detectable: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsValidationReport {
    pub status: ValidationStatus,
    pub findings: Vec<TermsFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_display_from_str_round_trip() {
        // WarrantyDeclaration
        for v in [
            WarrantyDeclaration::None,
            WarrantyDeclaration::Days30,
            WarrantyDeclaration::Days90,
            WarrantyDeclaration::Year1,
            WarrantyDeclaration::Year2,
        ] {
            assert_eq!(v.to_string().parse::<WarrantyDeclaration>().unwrap(), v);
        }

        // RefundDeclaration
        for v in [
            RefundDeclaration::None,
            RefundDeclaration::EuStatutory14Day,
            RefundDeclaration::Days30,
        ] {
            assert_eq!(v.to_string().parse::<RefundDeclaration>().unwrap(), v);
        }

        // RevocationDeclaration
        for v in [
            RevocationDeclaration::NotPossible,
            RevocationDeclaration::WithNotice7Day,
            RevocationDeclaration::Immediate,
        ] {
            assert_eq!(v.to_string().parse::<RevocationDeclaration>().unwrap(), v);
        }

        // ExpiryDeclaration
        for v in [
            ExpiryDeclaration::Perpetual,
            ExpiryDeclaration::TimeLimitedMonths(6),
            ExpiryDeclaration::TimeLimitedMonths(12),
            ExpiryDeclaration::TimeLimitedMonths(0),
        ] {
            assert_eq!(v.to_string().parse::<ExpiryDeclaration>().unwrap(), v);
        }

        // SupportScope
        for v in [
            SupportScope::BugsOnly,
            SupportScope::Installation,
            SupportScope::FullTechnical,
            SupportScope::Unlimited,
        ] {
            assert_eq!(v.to_string().parse::<SupportScope>().unwrap(), v);
        }

        // UpdatesPolicy
        for v in [
            UpdatesPolicy::None,
            UpdatesPolicy::Perpetual,
            UpdatesPolicy::IncludedMonths(6),
            UpdatesPolicy::IncludedMonths(24),
        ] {
            assert_eq!(v.to_string().parse::<UpdatesPolicy>().unwrap(), v);
        }

        // ConnectivityDeclaration
        for v in [
            ConnectivityDeclaration::AirGapped,
            ConnectivityDeclaration::Online,
            ConnectivityDeclaration::AlwaysOnline,
        ] {
            assert_eq!(v.to_string().parse::<ConnectivityDeclaration>().unwrap(), v);
        }

        // TransferDeclaration
        for v in [
            TransferDeclaration::NotAvailable,
            TransferDeclaration::VendorApproval,
        ] {
            assert_eq!(v.to_string().parse::<TransferDeclaration>().unwrap(), v);
        }
    }

    #[test]
    fn unknown_variants_are_errors() {
        assert!("Bogus".parse::<WarrantyDeclaration>().is_err());
        assert!(
            "TimeLimitedMonths(abc)"
                .parse::<ExpiryDeclaration>()
                .is_err()
        );
        assert!("IncludedMonths(xyz)".parse::<UpdatesPolicy>().is_err());
        assert!("TimeLimitedMonths".parse::<ExpiryDeclaration>().is_err());
    }
}
