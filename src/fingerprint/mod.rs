pub mod extractor;
pub mod identifier;

#[cfg(feature = "collect-linux")]
pub mod linux;

pub use extractor::{
    EncryptedShare, EnrollmentRecord, FuzzyExtractor, HardwareCollector, MasterSecret,
    MockCollector, compute_commitment,
};
pub use identifier::{HardwareIdentifier, IdentifierKind, IdentifierTier};

#[cfg(feature = "collect-linux")]
pub use linux::{CollectionAttempt, LinuxCollector};
