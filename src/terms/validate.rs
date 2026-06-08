use aho_corasick::AhoCorasick;

use super::template::block_text;
use super::types::{
    ConnectivityDeclaration, ExpiryDeclaration, FindingSeverity, RefundDeclaration,
    RevocationDeclaration, SupportScope, TermDeclarations, TermsFinding, TermsValidationReport,
    TransferDeclaration, UpdatesPolicy, ValidationStatus, WarrantyDeclaration,
};

/// Validates a vendor-edited Typst document against the declared terms.
///
/// Two-layer check:
/// 1. Mandatory blocks are compared byte-for-byte to the generated text -> `Conflict` on mismatch.
/// 2. Vendor-editable sections are scanned for deny-patterns -> `Warning` on match.
pub fn validate_terms(
    declarations: &TermDeclarations,
    typst_source: &str,
) -> TermsValidationReport {
    let mut findings = Vec::new();
    check_mandatory_blocks(declarations, typst_source, &mut findings);
    check_deny_patterns(declarations, typst_source, &mut findings);
    let status = compute_status(&findings);
    TermsValidationReport { status, findings }
}

const BLOCK_NAMES: &[&str] = &[
    "warranty",
    "refund",
    "revocation",
    "expiry",
    "support",
    "updates",
    "connectivity",
    "transfer",
];

fn extract_mandatory_blocks(source: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    for &name in BLOCK_NAMES {
        let start_marker = format!("/* zlicenser:block:{name}:start */");
        let end_marker = format!("/* zlicenser:block:{name}:end */");
        if let Some(start_pos) = source.find(&start_marker) {
            let after_start = start_pos + start_marker.len();
            // Skip the newline immediately after the start marker.
            let content_start = source[after_start..]
                .find(|c: char| c != '\n' && c != '\r')
                .map_or(after_start, |p| after_start + p);
            if let Some(end_pos) = source[content_start..].find(&end_marker) {
                let raw = &source[content_start..content_start + end_pos];
                // Trim a single trailing newline if present.
                let content = raw.trim_end_matches('\n').trim_end_matches('\r').to_owned();
                blocks.push((name.to_owned(), content));
            }
        }
    }
    blocks
}

fn extract_vendor_sections(source: &str) -> Vec<String> {
    let start_marker = "/* zlicenser:vendor:start */";
    let end_marker = "/* zlicenser:vendor:end */";
    let mut sections = Vec::new();
    let mut search_from = 0;
    while let Some(start_pos) = source[search_from..].find(start_marker) {
        let abs_start = search_from + start_pos + start_marker.len();
        if let Some(end_pos) = source[abs_start..].find(end_marker) {
            sections.push(source[abs_start..abs_start + end_pos].to_owned());
            search_from = abs_start + end_pos + end_marker.len();
        } else {
            break;
        }
    }
    sections
}

fn check_mandatory_blocks(
    decls: &TermDeclarations,
    source: &str,
    findings: &mut Vec<TermsFinding>,
) {
    let actual_blocks = extract_mandatory_blocks(source);

    for &name in BLOCK_NAMES {
        let expected = block_text(name, decls);
        let declared_value = declared_value_for_block(name, decls);

        let actual = actual_blocks
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.as_str());

        match actual {
            None => {
                findings.push(TermsFinding {
                    severity: FindingSeverity::Conflict,
                    declaration_key: name.to_owned(),
                    declared_value,
                    conflicting_excerpt: String::new(),
                    reason: format!("Mandatory block '{name}' is missing from the document."),
                    auto_detectable: true,
                });
            }
            Some(content) if content != expected => {
                let excerpt: String = content.chars().take(512).collect();
                findings.push(TermsFinding {
                    severity: FindingSeverity::Conflict,
                    declaration_key: name.to_owned(),
                    declared_value,
                    conflicting_excerpt: excerpt,
                    reason: "Mandatory block has been modified or is missing. \
                             Restore it to the generated text."
                        .to_owned(),
                    auto_detectable: true,
                });
            }
            Some(_) => {}
        }
    }
}

fn declared_value_for_block(name: &str, decls: &TermDeclarations) -> String {
    match name {
        "warranty" => decls.warranty.to_string(),
        "refund" => decls.refund.to_string(),
        "revocation" => decls.revocation.to_string(),
        "expiry" => decls.expiry.to_string(),
        "support" => decls.support_available.to_string(),
        "updates" => decls.updates_policy.to_string(),
        "connectivity" => decls.connectivity.to_string(),
        "transfer" => decls.transfer.to_string(),
        _ => String::new(),
    }
}

/// `(pattern_text, declaration_key, human_reason)`
#[allow(clippy::too_many_lines)]
fn applicable_deny_patterns(
    decls: &TermDeclarations,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut patterns = Vec::new();

    match decls.warranty {
        WarrantyDeclaration::None => {
            patterns.extend_from_slice(&[
                (
                    "warranty",
                    "warranty",
                    "Vendor text mentions warranty when none is declared",
                ),
                (
                    "warrantee",
                    "warranty",
                    "Vendor text mentions warranty when none is declared",
                ),
                (
                    "guaranteed to",
                    "warranty",
                    "Vendor text mentions warranty when none is declared",
                ),
            ]);
        }
        WarrantyDeclaration::Days30
        | WarrantyDeclaration::Days90
        | WarrantyDeclaration::Year1
        | WarrantyDeclaration::Year2 => {
            patterns.extend_from_slice(&[
                (
                    "no warranty",
                    "warranty",
                    "Vendor text contradicts declared warranty",
                ),
                (
                    "as-is",
                    "warranty",
                    "Vendor text contradicts declared warranty",
                ),
                (
                    "without warranty",
                    "warranty",
                    "Vendor text contradicts declared warranty",
                ),
                (
                    "as is",
                    "warranty",
                    "Vendor text contradicts declared warranty",
                ),
                (
                    "disclaim",
                    "warranty",
                    "Vendor text contradicts declared warranty",
                ),
            ]);
        }
    }

    if decls.refund == RefundDeclaration::None {
        patterns.extend_from_slice(&[
            (
                "refund",
                "refund",
                "Vendor text mentions refund when none declared",
            ),
            (
                "money back",
                "refund",
                "Vendor text mentions refund when none declared",
            ),
            (
                "return",
                "refund",
                "Vendor text mentions refund when none declared",
            ),
        ]);
    }

    match decls.revocation {
        RevocationDeclaration::NotPossible => {
            patterns.extend_from_slice(&[
                (
                    "revoke",
                    "revocation",
                    "Vendor text mentions revocation when declared not possible",
                ),
                (
                    "terminate your license",
                    "revocation",
                    "Vendor text mentions revocation when declared not possible",
                ),
                (
                    "suspend",
                    "revocation",
                    "Vendor text mentions revocation when declared not possible",
                ),
            ]);
        }
        RevocationDeclaration::WithNotice7Day => {
            patterns.extend_from_slice(&[
                (
                    "immediate termination",
                    "revocation",
                    "Vendor text implies immediate revocation without notice period",
                ),
                (
                    "revoke without notice",
                    "revocation",
                    "Vendor text implies immediate revocation without notice period",
                ),
            ]);
        }
        RevocationDeclaration::Immediate => {
            patterns.extend_from_slice(&[
                (
                    "notice before",
                    "revocation",
                    "Vendor text implies notice period when immediate revocation declared",
                ),
                (
                    "7 day notice",
                    "revocation",
                    "Vendor text implies notice period when immediate revocation declared",
                ),
                (
                    "30 day notice",
                    "revocation",
                    "Vendor text implies notice period when immediate revocation declared",
                ),
            ]);
        }
    }

    match decls.updates_policy {
        UpdatesPolicy::None => {
            patterns.extend_from_slice(&[
                (
                    "updates included",
                    "updates_policy",
                    "Vendor text implies updates when none declared",
                ),
                (
                    "free updates",
                    "updates_policy",
                    "Vendor text implies updates when none declared",
                ),
                (
                    "upgrade included",
                    "updates_policy",
                    "Vendor text implies updates when none declared",
                ),
                (
                    "lifetime updates",
                    "updates_policy",
                    "Vendor text implies updates when none declared",
                ),
            ]);
        }
        UpdatesPolicy::Perpetual => {
            patterns.extend_from_slice(&[
                (
                    "no updates",
                    "updates_policy",
                    "Vendor text contradicts perpetual updates",
                ),
                (
                    "updates not included",
                    "updates_policy",
                    "Vendor text contradicts perpetual updates",
                ),
                (
                    "no upgrade",
                    "updates_policy",
                    "Vendor text contradicts perpetual updates",
                ),
            ]);
        }
        UpdatesPolicy::IncludedMonths(_) => {
            patterns.extend_from_slice(&[
                (
                    "perpetual updates",
                    "updates_policy",
                    "Vendor text contradicts time-limited updates",
                ),
                (
                    "lifetime updates",
                    "updates_policy",
                    "Vendor text contradicts time-limited updates",
                ),
                (
                    "no updates",
                    "updates_policy",
                    "Vendor text contradicts time-limited updates",
                ),
            ]);
        }
    }

    match decls.expiry {
        ExpiryDeclaration::Perpetual => {
            patterns.extend_from_slice(&[
                (
                    "expires",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
                (
                    "expiry",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
                (
                    "time-limited",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
                (
                    "subscription",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
                (
                    "license term",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
                (
                    "renewal",
                    "expiry",
                    "Vendor text implies expiry when perpetual declared",
                ),
            ]);
        }
        ExpiryDeclaration::TimeLimitedMonths(_) => {
            patterns.extend_from_slice(&[
                (
                    "perpetual",
                    "expiry",
                    "Vendor text implies no expiry when time-limited declared",
                ),
                (
                    "lifetime license",
                    "expiry",
                    "Vendor text implies no expiry when time-limited declared",
                ),
                (
                    "never expires",
                    "expiry",
                    "Vendor text implies no expiry when time-limited declared",
                ),
                (
                    "no expiry",
                    "expiry",
                    "Vendor text implies no expiry when time-limited declared",
                ),
            ]);
        }
    }

    if !decls.support_available {
        patterns.extend_from_slice(&[
            (
                "support",
                "support_available",
                "Vendor text mentions support when unavailable",
            ),
            (
                "help desk",
                "support_available",
                "Vendor text mentions support when unavailable",
            ),
            (
                "helpdesk",
                "support_available",
                "Vendor text mentions support when unavailable",
            ),
            (
                "customer service",
                "support_available",
                "Vendor text mentions support when unavailable",
            ),
            (
                "technical assistance",
                "support_available",
                "Vendor text mentions support when unavailable",
            ),
        ]);
    }

    if let Some(scope) = decls.support_scope {
        match scope {
            SupportScope::BugsOnly => {
                patterns.extend_from_slice(&[
                    (
                        "unlimited support",
                        "support_scope",
                        "Vendor text implies broader support than declared",
                    ),
                    (
                        "full support",
                        "support_scope",
                        "Vendor text implies broader support than declared",
                    ),
                    (
                        "installation support",
                        "support_scope",
                        "Vendor text implies broader support than declared",
                    ),
                ]);
            }
            SupportScope::FullTechnical => {
                patterns.extend_from_slice(&[
                    (
                        "bug fix only",
                        "support_scope",
                        "Vendor text implies narrower support than declared",
                    ),
                    (
                        "bugs only",
                        "support_scope",
                        "Vendor text implies narrower support than declared",
                    ),
                ]);
            }
            _ => {}
        }
    }

    match decls.connectivity {
        ConnectivityDeclaration::AirGapped => {
            patterns.extend_from_slice(&[
                (
                    "requires internet",
                    "connectivity",
                    "Vendor text implies internet requirement for air-gapped product",
                ),
                (
                    "online activation",
                    "connectivity",
                    "Vendor text implies internet requirement for air-gapped product",
                ),
                (
                    "phone home",
                    "connectivity",
                    "Vendor text implies internet requirement for air-gapped product",
                ),
            ]);
        }
        ConnectivityDeclaration::AlwaysOnline => {
            patterns.extend_from_slice(&[
                (
                    "offline",
                    "connectivity",
                    "Vendor text implies offline operation for always-online product",
                ),
                (
                    "air-gapped",
                    "connectivity",
                    "Vendor text implies offline operation for always-online product",
                ),
                (
                    "no internet required",
                    "connectivity",
                    "Vendor text implies offline operation for always-online product",
                ),
            ]);
        }
        _ => {}
    }

    if decls.transfer == TransferDeclaration::NotAvailable {
        patterns.extend_from_slice(&[
            (
                "transfer",
                "transfer",
                "Vendor text mentions transfer when declared not available",
            ),
            (
                "reassign",
                "transfer",
                "Vendor text mentions transfer when declared not available",
            ),
            (
                "transferable",
                "transfer",
                "Vendor text mentions transfer when declared not available",
            ),
        ]);
    }

    patterns
}

fn build_automaton(patterns: &[&str]) -> AhoCorasick {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns)
        // Static patterns known at compile time , construction cannot fail.
        .expect("deny-pattern automaton uses compile-time static patterns")
}

fn check_deny_patterns(decls: &TermDeclarations, source: &str, findings: &mut Vec<TermsFinding>) {
    let deny = applicable_deny_patterns(decls);
    if deny.is_empty() {
        return;
    }
    let patterns: Vec<&str> = deny.iter().map(|(p, _, _)| *p).collect();
    let ac = build_automaton(&patterns);

    for section in extract_vendor_sections(source) {
        for mat in ac.find_iter(&section) {
            let (pattern, key, reason) = deny[mat.pattern().as_usize()];
            let auto_detectable = !is_inside_typst_string(&section, mat.start());
            findings.push(TermsFinding {
                severity: FindingSeverity::Warning,
                declaration_key: (*key).to_owned(),
                declared_value: declared_value_for_block(key, decls),
                conflicting_excerpt: (*pattern).to_owned(),
                reason: (*reason).to_owned(),
                auto_detectable,
            });
        }
    }
}

/// Best-effort heuristic: count unescaped `"` before `byte_offset`.
/// An odd count means the match is inside a Typst string literal.
fn is_inside_typst_string(text: &str, byte_offset: usize) -> bool {
    text[..byte_offset].chars().filter(|&c| c == '"').count() % 2 == 1
}

fn compute_status(findings: &[TermsFinding]) -> ValidationStatus {
    if findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Conflict)
    {
        ValidationStatus::Conflicts
    } else if findings.is_empty() {
        ValidationStatus::Valid
    } else {
        ValidationStatus::Warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::template::generate_template;

    fn base_decls() -> TermDeclarations {
        use crate::terms::types::{
            ConnectivityDeclaration, ExpiryDeclaration, RefundDeclaration, RevocationDeclaration,
            SupportScope, TransferDeclaration, UpdatesPolicy, WarrantyDeclaration,
        };
        TermDeclarations {
            warranty: WarrantyDeclaration::Days30,
            refund: RefundDeclaration::EuStatutory14Day,
            revocation: RevocationDeclaration::WithNotice7Day,
            expiry: ExpiryDeclaration::Perpetual,
            support_available: true,
            support_scope: Some(SupportScope::FullTechnical),
            updates_policy: UpdatesPolicy::Perpetual,
            connectivity: ConnectivityDeclaration::Online,
            transfer: TransferDeclaration::VendorApproval,
        }
    }

    #[test]
    fn clean_document_is_valid() {
        let decls = base_decls();
        let tmpl = generate_template(&decls);
        let report = validate_terms(&decls, &tmpl);
        assert_eq!(
            report.status,
            ValidationStatus::Valid,
            "{:?}",
            report.findings
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn modified_mandatory_block_is_conflict() {
        let decls = base_decls();
        let tmpl = generate_template(&decls);
        let tampered = tmpl.replace(
            "This software is warranted to perform substantially as described for 30 days",
            "This software is warranted to perform substantially as described for 99 days",
        );
        let report = validate_terms(&decls, &tampered);
        assert_eq!(report.status, ValidationStatus::Conflicts);
        let conflicts: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Conflict)
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].declaration_key, "warranty");
    }

    #[test]
    fn missing_mandatory_block_is_conflict() {
        let decls = base_decls();
        let tmpl = generate_template(&decls);
        let start_marker = "/* zlicenser:block:warranty:start */";
        let end_marker = "/* zlicenser:block:warranty:end */";
        let start = tmpl.find(start_marker).unwrap();
        let end = tmpl.find(end_marker).unwrap() + end_marker.len();
        let stripped = format!("{}{}", &tmpl[..start], &tmpl[end..]);
        let report = validate_terms(&decls, &stripped);
        assert_eq!(report.status, ValidationStatus::Conflicts);
        let missing: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.declaration_key == "warranty" && f.severity == FindingSeverity::Conflict)
            .collect();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].reason.contains("missing"));
    }

    #[test]
    fn deny_pattern_in_vendor_section_is_warning() {
        // warranty=None -> "warranty" is a deny pattern in vendor sections.
        use crate::terms::types::WarrantyDeclaration;
        let decls = TermDeclarations {
            warranty: WarrantyDeclaration::None,
            ..base_decls()
        };
        // Rebuild template with new warranty value so mandatory block passes.
        let tmpl = generate_template(&decls);
        // Inject a deny-pattern string into a vendor section.
        let injected = tmpl.replacen(
            "// Your product name and introductory text go here.",
            "// Your product name and introductory text go here.\n// We offer a great warranty!",
            1,
        );
        let report = validate_terms(&decls, &injected);
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Warning && f.declaration_key == "warranty")
            .collect();
        assert!(!warnings.is_empty(), "expected a warranty Warning");
        assert!(warnings[0].auto_detectable);
    }

    #[test]
    fn deny_pattern_inside_typst_string_is_ambiguous() {
        use crate::terms::types::WarrantyDeclaration;
        let decls = TermDeclarations {
            warranty: WarrantyDeclaration::None,
            ..base_decls()
        };
        let tmpl = generate_template(&decls);
        // Place the deny-pattern inside a quoted Typst string literal.
        let injected = tmpl.replacen(
            "// Your product name and introductory text go here.",
            "// Your product name and introductory text go here.\n#let x = \"warranty disclaimer\"",
            1,
        );
        let report = validate_terms(&decls, &injected);
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Warning && f.declaration_key == "warranty")
            .collect();
        assert!(!warnings.is_empty());
        // The pattern appears after an odd number of '"' -> auto_detectable = false.
        assert!(!warnings[0].auto_detectable);
    }

    #[test]
    fn multiple_findings_status_is_conflicts() {
        let decls = base_decls();
        let tmpl = generate_template(&decls);
        // Tamper warranty block (Conflict) and expiry block (Conflict) simultaneously.
        let tampered = tmpl
            .replace(
                "This software is warranted to perform substantially as described for 30 days",
                "This software is warranted for an unspecified period",
            )
            .replace(
                "This license is perpetual and does not expire.",
                "This license expires after one year.",
            );
        let report = validate_terms(&decls, &tampered);
        assert_eq!(report.status, ValidationStatus::Conflicts);
        assert!(
            report
                .findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Conflict)
                .count()
                >= 2
        );
    }

    #[test]
    fn only_warnings_status_is_warnings() {
        use crate::terms::types::WarrantyDeclaration;
        let decls = TermDeclarations {
            warranty: WarrantyDeclaration::None,
            ..base_decls()
        };
        let tmpl = generate_template(&decls);
        // Add two deny-pattern matches in vendor sections, no block tampering.
        let injected = tmpl.replacen(
            "// Your product name and introductory text go here.",
            "// Your product name and introductory text go here.\n// warranty and warrantee",
            1,
        );
        let report = validate_terms(&decls, &injected);
        assert_eq!(report.status, ValidationStatus::Warnings);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.severity == FindingSeverity::Warning)
        );
    }
}
