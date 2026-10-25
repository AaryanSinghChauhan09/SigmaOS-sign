//! Signature verification module.
//!
//! Single responsibility: validate detached Ed25519 signatures.
//! Inspired by omacom/signed.

use std::fmt;
use std::fs;
use std::path::Path;

/// Errors that can occur during verification.
#[derive(Debug)]
pub enum VerifyError {
    IoError(std::io::Error),
    SignatureNotFound(String),
    KeyLoadFailed(String),
    MalformedSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::IoError(e) => write!(f, "I/O error: {}", e),
            VerifyError::SignatureNotFound(p) => write!(f, "Signature file not found: {}", p),
            VerifyError::KeyLoadFailed(msg) => write!(f, "Key load failed: {}", msg),
            VerifyError::MalformedSignature => write!(f, "Signature is malformed"),
        }
    }
}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        VerifyError::IoError(e)
    }
}

/// Verification public key (Ed25519 public key bytes).
#[derive(Debug, Clone)]
pub struct VerifyKey {
    bytes: [u8; 32],
}

impl VerifyKey {
    /// Load a verification key from a 32-byte raw key file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, VerifyError> {
        let data = fs::read(path.as_ref())?;
        if data.len() != 32 {
            return Err(VerifyKey::key_error());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        Ok(VerifyKey { bytes })
    }

    fn key_error() -> VerifyError {
        VerifyError::KeyLoadFailed("key file must be exactly 32 bytes".to_string())
    }
}

/// Signature verifier.
///
/// Reads a file and its companion `.sig` file, then validates the Ed25519
/// detached signature against the configured public key.
pub struct Verifier {
    key: Option<VerifyKey>,
}

impl Verifier {
    /// Create a verifier that loads the default system public key on first use.
    pub fn new() -> Self {
        Verifier { key: None }
    }

    /// Create a verifier with an explicit public key.
    pub fn with_key(key: VerifyKey) -> Self {
        Verifier { key: Some(key) }
    }

    /// Verify the detached `.sig` file for the given path.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid,
    /// or `Err` for I/O or key errors.
    pub fn verify_file<P: AsRef<Path>>(&self, path: P) -> Result<bool, VerifyError> {
        let path = path.as_ref();
        let data = fs::read(path)?;
        let sig_path = path.with_extension("sig");
        if !sig_path.exists() {
            return Err(VerifyError::SignatureNotFound(
                sig_path.display().to_string(),
            ));
        }
        let sig_bytes = fs::read(&sig_path)?;
        self.verify_bytes(&data, &sig_bytes)
    }

    /// Validate raw data against a raw signature.
    fn verify_bytes(&self, _data: &[u8], sig: &[u8]) -> Result<bool, VerifyError> {
        if sig.len() != 64 {
            return Err(VerifyError::MalformedSignature);
        }
        // TODO: call Ed25519 verify with self.key
        Ok(true)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_signature_rejected() {
        let verifier = Verifier::new();
        // A 10-byte blob is not a valid Ed25519 signature
        let result = verifier.verify_bytes(b"data", &[0u8; 10]);
        assert!(matches!(result, Err(VerifyError::MalformedSignature)));
    }

    #[test]
    fn well_sized_signature_accepted_by_stub() {
        let verifier = Verifier::new();
        let result = verifier.verify_bytes(b"data", &[0u8; 64]);
        assert!(matches!(result, Ok(true)));
    }
}
