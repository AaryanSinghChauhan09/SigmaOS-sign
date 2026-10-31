//! SigmaOS Digital Signature Library
//!
//! Provides cryptographic signing and verification for SigmaOS packages
//! and binaries. Inspired by omacom/signed.

pub mod signer;
pub mod verifier;

pub use signer::Signer;
pub use signer::SigningKey;
pub use verifier::Verifier;
pub use verifier::VerifyKey;
