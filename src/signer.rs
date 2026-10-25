//! Digital signature creation module.
//!
//! Single responsibility: produce detached Ed25519 signatures for files.
//! Inspired by omacom/signed.

use std::fmt;
use std::fs;
use std::path::Path;

/// Errors that can occur during signing.
#[derive(Debug)]
pub enum SignError {
    IoError(std::io::Error),
    KeyLoadFailed(String),
    SignFailed(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::IoError(e) => write!(f, "I/O error: {}", e),
            SignError::KeyLoadFailed(msg) => write!(f, "Key load failed: {}", msg),
            SignError::SignFailed(msg) => write!(f, "Signing failed: {}", msg),
        }
    }
}

impl From<std::io::Error> for SignError {
    fn from(e: std::io::Error) -> Self {
        SignError::IoError(e)
    }
}

/// Signing key material (Ed25519 private key bytes).
#[derive(Debug, Clone)]
pub struct SigningKey {
    bytes: [u8; 32],
}

impl SigningKey {
    /// Load a signing key from a 32-byte raw key file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignError> {
        let data = fs::read(path.as_ref())?;
        if data.len() != 32 {
            return Err(SignError::KeyLoadFailed(
                "key file must be exactly 32 bytes".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        Ok(SigningKey { bytes })
    }

    /// Generate an ephemeral random key (for testing / key generation).
    pub fn generate() -> Self {
        // TODO: replace with a proper CSPRNG call
        SigningKey { bytes: [0u8; 32] }
    }
}

/// File signer.
///
/// Reads a file, produces an Ed25519 detached signature, and writes a `.sig`
/// file next to the original.
pub struct Signer {
    key: Option<SigningKey>,
}

impl Signer {
    /// Create a signer without a pre-loaded key (key loaded lazily from default path).
    pub fn new() -> Self {
        Signer { key: None }
    }

    /// Create a signer with an explicit signing key.
    pub fn with_key(key: SigningKey) -> Self {
        Signer { key: Some(key) }
    }

    /// Sign a file, writing a detached `.sig` next to it.
    pub fn sign_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SignError> {
        let path = path.as_ref();
        let data = fs::read(path)?;
        let signature = self.sign_bytes(&data)?;
        let sig_path = path.with_extension("sig");
        fs::write(&sig_path, &signature)?;
        Ok(())
    }

    /// Produce an Ed25519 signature over raw bytes.
    fn sign_bytes(&self, _data: &[u8]) -> Result<Vec<u8>, SignError> {
        // TODO: call Ed25519 impl with self.key
        Ok(vec![0u8; 64])
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sign_temp_file() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"hello sigma").expect("write");
        let signer = Signer::new();
        // Signing should not error (stub implementation)
        assert!(signer.sign_file(f.path()).is_ok());
    }
}
