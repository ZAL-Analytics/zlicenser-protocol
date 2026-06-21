use std::fmt::Write as _;

use super::types::{
    ConnectivityDeclaration, ExpiryDeclaration, RefundDeclaration, RevocationDeclaration,
    SupportScope, TermDeclarations, TransferDeclaration, UpdatesPolicy, WarrantyDeclaration,
};

/// Generates a Typst terms template pre-filled with mandatory blocks derived from `decls`.
///
/// Vendors edit only the `/* zlicenser:vendor:start */ ... /* zlicenser:vendor:end */` regions.
/// Mandatory block content is fixed; any modification is flagged as a `Conflict` by
/// [`crate::terms::validate_terms`].
pub fn generate_template(decls: &TermDeclarations) -> String {
    let blocks = [
        "warranty",
        "refund",
        "revocation",
        "expiry",
        "support",
        "updates",
        "connectivity",
        "transfer",
    ];

    let mut out = String::with_capacity(4096);
    out.push_str("// zlicenser-generated terms template , v1\n");
    out.push_str("// Edit only the regions between /* zlicenser:vendor:start */ and /* zlicenser:vendor:end */.\n");
    out.push_str(
        "// Mandatory blocks are protected; any modification will be flagged as a Conflict.\n\n",
    );

    // Opening vendor section , product name and intro.
    out.push_str("/* zlicenser:vendor:start */\n");
    out.push_str("// Your product name and introductory text go here.\n");
    out.push_str("/* zlicenser:vendor:end */\n\n");

    for name in blocks {
        let _ = writeln!(out, "/* zlicenser:block:{name}:start */");
        out.push_str(&block_text(name, decls));
        out.push('\n');
        let _ = write!(out, "/* zlicenser:block:{name}:end */\n\n");

        // Each mandatory block is followed by a vendor section.
        out.push_str("/* zlicenser:vendor:start */\n");
        out.push_str("/* zlicenser:vendor:end */\n\n");
    }

    out
}

/// Returns the mandatory block text for the given block `key` and declarations.
///
/// This is the **single source of truth** for mandatory block content. Both
/// [`generate_template`] and `validate_terms` call this function.
///
/// # Stability
/// Block text is fixed at first deployment. Changing it after any vendor has used the template
/// invalidates all existing vendor documents. Introduce a new template version instead.
pub(super) fn block_text(key: &str, decls: &TermDeclarations) -> String {
    match key {
        "warranty" => warranty_text(decls.warranty),
        "refund" => refund_text(decls.refund),
        "revocation" => revocation_text(decls.revocation),
        "expiry" => expiry_text(decls.expiry),
        "support" => support_text(decls.support_available, decls.support_scope),
        "updates" => updates_text(decls.updates_policy),
        "connectivity" => connectivity_text(decls.connectivity),
        "transfer" => transfer_text(decls.transfer),
        _ => String::new(),
    }
}

fn warranty_text(w: WarrantyDeclaration) -> String {
    match w {
        WarrantyDeclaration::None => {
            "This software is provided WITHOUT ANY WARRANTY of any kind, to the maximum extent \
             permitted by applicable law."
                .to_owned()
        }
        WarrantyDeclaration::Days30 => {
            "This software is warranted to perform substantially as described for 30 days from \
             the date of purchase. Your sole remedy for a warranty breach is a repair, \
             replacement, or refund at the vendor's discretion."
                .to_owned()
        }
        WarrantyDeclaration::Days90 => {
            "This software is warranted to perform substantially as described for 90 days from \
             the date of purchase. Your sole remedy for a warranty breach is a repair, \
             replacement, or refund at the vendor's discretion."
                .to_owned()
        }
        WarrantyDeclaration::Year1 => {
            "This software is warranted to perform substantially as described for one year from \
             the date of purchase. Your sole remedy for a warranty breach is a repair, \
             replacement, or refund at the vendor's discretion."
                .to_owned()
        }
        WarrantyDeclaration::Year2 => {
            "This software is warranted to perform substantially as described for two years from \
             the date of purchase. Your sole remedy for a warranty breach is a repair, \
             replacement, or refund at the vendor's discretion."
                .to_owned()
        }
    }
}

fn refund_text(r: RefundDeclaration) -> String {
    match r {
        RefundDeclaration::None => "All sales are final. No refunds are offered.".to_owned(),
        RefundDeclaration::EuStatutory14Day => {
            "You have the right to withdraw from this purchase within 14 days under EU Consumer \
             Rights Directive 2011/83/EU, unless digital content delivery has commenced with \
             your prior consent."
                .to_owned()
        }
        RefundDeclaration::Days30 => {
            "A full refund is available within 30 days of purchase if the software does not \
             perform substantially as described."
                .to_owned()
        }
    }
}

fn revocation_text(r: RevocationDeclaration) -> String {
    match r {
        RevocationDeclaration::NotPossible => {
            "Once issued, this license cannot be revoked except in cases of fraud or material \
             breach of these terms."
                .to_owned()
        }
        RevocationDeclaration::WithNotice7Day => {
            "The vendor reserves the right to revoke this license with 7 days written notice \
             in the event of a material breach of these terms."
                .to_owned()
        }
        RevocationDeclaration::Immediate => {
            "The vendor reserves the right to revoke this license immediately upon a material \
             breach of these terms, without prior notice."
                .to_owned()
        }
    }
}

fn expiry_text(e: ExpiryDeclaration) -> String {
    match e {
        ExpiryDeclaration::Perpetual => "This license is perpetual and does not expire.".to_owned(),
        ExpiryDeclaration::TimeLimitedMonths(n) => {
            format!(
                "This license is valid for {n} months from the date of activation, after which \
                 it expires and the software will cease to function."
            )
        }
    }
}

fn support_text(available: bool, scope: Option<SupportScope>) -> String {
    if !available {
        return "No support is provided for this software. Use at your own risk.".to_owned();
    }
    let scope_desc = match scope {
        None | Some(SupportScope::BugsOnly) => {
            "Support is limited to confirmed software defects (bug fixes) only."
        }
        Some(SupportScope::Installation) => {
            "Support covers installation assistance and confirmed software defects."
        }
        Some(SupportScope::FullTechnical) => {
            "Full technical support is provided, including installation, configuration, \
             and troubleshooting."
        }
        Some(SupportScope::Unlimited) => {
            "Unlimited support is provided at the vendor's discretion, covering all aspects \
             of software use."
        }
    };
    scope_desc.to_owned()
}

fn updates_text(u: UpdatesPolicy) -> String {
    match u {
        UpdatesPolicy::None => {
            "No software updates are included with this license. Updates, if available, \
             require a separate purchase."
                .to_owned()
        }
        UpdatesPolicy::IncludedMonths(n) => {
            format!(
                "Software updates are included for {n} months from the date of purchase. \
                 After this period, updates require a separate purchase."
            )
        }
        UpdatesPolicy::Perpetual => {
            "All future updates to this software are included with this license at no \
             additional cost."
                .to_owned()
        }
    }
}

fn connectivity_text(c: ConnectivityDeclaration) -> String {
    match c {
        ConnectivityDeclaration::AirGapped => {
            "This software operates entirely offline. It does not require internet access \
             and makes no network connections."
                .to_owned()
        }
        ConnectivityDeclaration::Online => {
            "This software may use an internet connection for license verification and \
             optional features. Offline use may be limited."
                .to_owned()
        }
        ConnectivityDeclaration::AlwaysOnline => {
            "This software requires a continuous internet connection to operate. \
             Functionality is unavailable without connectivity."
                .to_owned()
        }
    }
}

fn transfer_text(t: TransferDeclaration) -> String {
    match t {
        TransferDeclaration::NotAvailable => {
            "This license is non-transferable and may not be assigned, sold, or otherwise \
             transferred to any third party."
                .to_owned()
        }
        TransferDeclaration::VendorApproval => {
            "This license may be transferred to another party subject to prior written \
             approval from the vendor."
                .to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terms::types::{
        ConnectivityDeclaration, ExpiryDeclaration, RefundDeclaration, RevocationDeclaration,
        TermDeclarations, TransferDeclaration, UpdatesPolicy, WarrantyDeclaration,
    };

    fn sample_decls() -> TermDeclarations {
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
    fn template_contains_all_blocks() {
        let decls = sample_decls();
        let tmpl = generate_template(&decls);
        for block in [
            "warranty",
            "refund",
            "revocation",
            "expiry",
            "support",
            "updates",
            "connectivity",
            "transfer",
        ] {
            assert!(
                tmpl.contains(&format!("/* zlicenser:block:{block}:start */")),
                "missing start marker for {block}"
            );
            assert!(
                tmpl.contains(&format!("/* zlicenser:block:{block}:end */")),
                "missing end marker for {block}"
            );
        }
    }

    #[test]
    fn template_block_text_stable() {
        let decls = sample_decls();
        for block in [
            "warranty",
            "refund",
            "revocation",
            "expiry",
            "support",
            "updates",
            "connectivity",
            "transfer",
        ] {
            let first = block_text(block, &decls);
            let second = block_text(block, &decls);
            assert_eq!(first, second, "block_text for {block} is not stable");
        }
    }

    #[cfg(feature = "terms")]
    mod proptest_tests {
        use super::*;
        use crate::terms::types::ValidationStatus;
        use crate::terms::validate::validate_terms;
        use proptest::prelude::*;

        fn arb_warranty() -> impl Strategy<Value = WarrantyDeclaration> {
            prop_oneof![
                Just(WarrantyDeclaration::None),
                Just(WarrantyDeclaration::Days30),
                Just(WarrantyDeclaration::Days90),
                Just(WarrantyDeclaration::Year1),
                Just(WarrantyDeclaration::Year2),
            ]
        }

        fn arb_refund() -> impl Strategy<Value = RefundDeclaration> {
            prop_oneof![
                Just(RefundDeclaration::None),
                Just(RefundDeclaration::EuStatutory14Day),
                Just(RefundDeclaration::Days30),
            ]
        }

        fn arb_revocation() -> impl Strategy<Value = RevocationDeclaration> {
            prop_oneof![
                Just(RevocationDeclaration::NotPossible),
                Just(RevocationDeclaration::WithNotice7Day),
                Just(RevocationDeclaration::Immediate),
            ]
        }

        fn arb_expiry() -> impl Strategy<Value = ExpiryDeclaration> {
            prop_oneof![
                Just(ExpiryDeclaration::Perpetual),
                (1u32..=120u32).prop_map(ExpiryDeclaration::TimeLimitedMonths),
            ]
        }

        fn arb_support_scope() -> impl Strategy<Value = Option<SupportScope>> {
            prop_oneof![
                Just(None),
                Just(Some(SupportScope::BugsOnly)),
                Just(Some(SupportScope::Installation)),
                Just(Some(SupportScope::FullTechnical)),
                Just(Some(SupportScope::Unlimited)),
            ]
        }

        fn arb_updates() -> impl Strategy<Value = UpdatesPolicy> {
            prop_oneof![
                Just(UpdatesPolicy::None),
                Just(UpdatesPolicy::Perpetual),
                (1u32..=60u32).prop_map(UpdatesPolicy::IncludedMonths),
            ]
        }

        fn arb_connectivity() -> impl Strategy<Value = ConnectivityDeclaration> {
            prop_oneof![
                Just(ConnectivityDeclaration::AirGapped),
                Just(ConnectivityDeclaration::Online),
                Just(ConnectivityDeclaration::AlwaysOnline),
            ]
        }

        fn arb_transfer() -> impl Strategy<Value = TransferDeclaration> {
            prop_oneof![
                Just(TransferDeclaration::NotAvailable),
                Just(TransferDeclaration::VendorApproval),
            ]
        }

        proptest! {
            #[test]
            fn proptest_template_round_trip(
                warranty in arb_warranty(),
                refund in arb_refund(),
                revocation in arb_revocation(),
                expiry in arb_expiry(),
                support_available in any::<bool>(),
                support_scope in arb_support_scope(),
                updates_policy in arb_updates(),
                connectivity in arb_connectivity(),
                transfer in arb_transfer(),
            ) {
                let decls = TermDeclarations {
                    warranty,
                    refund,
                    revocation,
                    expiry,
                    support_available,
                    support_scope,
                    updates_policy,
                    connectivity,
                    transfer,
                };
                let tmpl = generate_template(&decls);
                let report = validate_terms(&decls, &tmpl);
                prop_assert_eq!(
                    report.status,
                    ValidationStatus::Valid,
                    "generated template did not validate as Valid: {:?}",
                    report.findings
                );
            }
        }
    }
}
