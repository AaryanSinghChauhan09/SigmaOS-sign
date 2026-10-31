//! Digital signature creation module.
//!
//! Single responsibility: produce detached Ed25519 signatures for files.
//! Inspired by omacom/signed.

use crate::verifier::VerifyKey;
use ed25519_dalek::{Signer as DalekSigner, SigningKey as DalekSigningKey};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Errors that can occur during signing.
#[derive(Debug)]
pub enum SignError {
    IoError(std::io::Error),
    KeyLoadFailed(String),
    KeyGenerationFailed(String),
    MissingSigningKey,
    SignFailed(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::IoError(e) => write!(f, "I/O error: {}", e),
            SignError::KeyLoadFailed(msg) => write!(f, "Key load failed: {}", msg),
            SignError::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            SignError::MissingSigningKey => write!(f, "No signing key is configured"),
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
pub struct SigningKey {
    pub(crate) inner: DalekSigningKey,
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
        Ok(Self::from_bytes(bytes))
    }

    /// Construct a signing key from its 32-byte Ed25519 seed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: DalekSigningKey::from_bytes(&bytes),
        }
    }

    /// Generate a signing key using the operating system's cryptographic RNG.
    pub fn generate() -> Result<Self, SignError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|error| SignError::KeyGenerationFailed(error.to_string()))?;
        Ok(Self::from_bytes(bytes))
    }

    /// Return the public key corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyKey {
        VerifyKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Write the raw 32-byte seed to a new owner-readable file.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SignError> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&self.inner.to_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey([REDACTED])")
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
    /// Create a signer without a key. Signing fails until a key is supplied.
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
    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let key = self.key.as_ref().ok_or(SignError::MissingSigningKey)?;
        Ok(key.inner.sign(data).to_bytes().to_vec())
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
    use std::fs;

    #[test]
    fn sign_temp_file() {
        let path = std::env::temp_dir().join(format!("sigma-sign-test-{}", std::process::id()));
        fs::write(&path, b"hello sigma").expect("write");
        let key = SigningKey::generate().expect("OS randomness available");
        let signer = Signer::with_key(key);
        assert!(signer.sign_file(&path).is_ok());
        fs::remove_file(&path).ok();
        fs::remove_file(path.with_extension("sig")).ok();
    }
}
