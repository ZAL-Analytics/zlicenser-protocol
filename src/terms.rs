mod template;
mod types;
mod validate;

pub use template::generate_template;
pub use types::{
    ConnectivityDeclaration, ExpiryDeclaration, FindingSeverity, RefundDeclaration,
    RevocationDeclaration, SupportScope, TermDeclarations, TermsFinding, TermsValidationReport,
    TransferDeclaration, UpdatesPolicy, ValidationStatus, WarrantyDeclaration,
};
pub use validate::validate_terms;
