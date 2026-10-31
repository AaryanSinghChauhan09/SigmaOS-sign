//! Signature verification module.
//!
//! Single responsibility: validate detached Ed25519 signatures.
//! Inspired by omacom/signed.

use ed25519_dalek::{Signature, VerifyingKey as DalekVerifyingKey};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Errors that can occur during verification.
#[derive(Debug)]
pub enum VerifyError {
    IoError(std::io::Error),
    SignatureNotFound(String),
    KeyLoadFailed(String),
    MalformedSignature,
    MissingVerificationKey,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::IoError(e) => write!(f, "I/O error: {}", e),
            VerifyError::SignatureNotFound(p) => write!(f, "Signature file not found: {}", p),
            VerifyError::KeyLoadFailed(msg) => write!(f, "Key load failed: {}", msg),
            VerifyError::MalformedSignature => write!(f, "Signature is malformed"),
            VerifyError::MissingVerificationKey => write!(f, "No verification key is configured"),
        }
    }
}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        VerifyError::IoError(e)
    }
}

/// Verification public key (Ed25519 public key bytes).
pub struct VerifyKey {
    pub(crate) inner: DalekVerifyingKey,
}

impl VerifyKey {
    /// Load a verification key from a 32-byte raw key file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, VerifyError> {
        let data = fs::read(path.as_ref())?;
        if data.len() != 32 {
            return Err(VerifyError::KeyLoadFailed(
                "key file must be exactly 32 bytes".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        Self::from_bytes(bytes)
    }

    /// Construct a verification key from its raw 32-byte encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, VerifyError> {
        let inner = DalekVerifyingKey::from_bytes(&bytes)
            .map_err(|error| VerifyError::KeyLoadFailed(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Write the raw public key to a new file.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), VerifyError> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&self.inner.to_bytes())?;
        file.sync_all()?;
        Ok(())
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
    /// Create a verifier without a key. Verification fails until a key is supplied.
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
    fn verify_bytes(&self, data: &[u8], sig: &[u8]) -> Result<bool, VerifyError> {
        if sig.len() != 64 {
            return Err(VerifyError::MalformedSignature);
        }
        let key = self
            .key
            .as_ref()
            .ok_or(VerifyError::MissingVerificationKey)?;
        let signature = Signature::from_slice(sig).map_err(|_| VerifyError::MalformedSignature)?;
        Ok(key.inner.verify_strict(data, &signature).is_ok())
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
    fn valid_signature_accepts_only_its_message() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signing_key.sign(b"data");
        let verifier = Verifier::with_key(VerifyKey {
            inner: signing_key.verifying_key(),
        });
        assert!(matches!(
            verifier.verify_bytes(b"data", &signature.to_bytes()),
            Ok(true)
        ));
        assert!(matches!(
            verifier.verify_bytes(b"other", &signature.to_bytes()),
            Ok(false)
        ));
    }
}
