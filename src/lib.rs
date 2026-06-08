#![warn(clippy::all, clippy::pedantic)]
#![deny(unsafe_op_in_unsafe_fn)]
// Pre-existing documentation debt; fix incrementally as code is touched .
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown
)]

pub mod crypto;
pub mod error;
pub mod message;
pub mod wire;

pub mod evidence;
pub mod fingerprint;
pub mod tsa;

#[cfg(feature = "terms")]
pub mod terms;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
