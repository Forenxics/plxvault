//! Error types for PlxVault Core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Certificate signing failed: {0}")]
    Signing(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("Invalid CSR: {0}")]
    InvalidCsr(String),

    #[error("Certificate parsing failed: {0}")]
    Parsing(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("HSM error: {0}")]
    Hsm(String),

    #[error("Post-quantum crypto error: {0}")]
    PostQuantum(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Revocation error: {0}")]
    Revocation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
