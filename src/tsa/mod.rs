pub mod verify;

#[cfg(feature = "tsa-clients")]
pub mod providers;

/// In-process mock TSA server for integration testing.
/// Only available with `--features tsa-test-utils`.
#[cfg(feature = "tsa-test-utils")]
pub mod mock;

#[cfg(feature = "tsa-verify")]
pub use verify::{TsaProvider, VerifiedToken};
