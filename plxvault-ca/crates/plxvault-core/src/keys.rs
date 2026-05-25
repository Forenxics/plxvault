//! Key generation for classical and post-quantum algorithms

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Supported key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    // Classical algorithms
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,

    // Post-Quantum (NIST standards)
    MlDsa44,  // Dilithium2 - NIST Level 2
    MlDsa65,  // Dilithium3 - NIST Level 3
    MlDsa87,  // Dilithium5 - NIST Level 5

    // Hybrid (classical + PQC)
    EcdsaP256MlDsa65,
    Ed25519MlDsa65,
}

impl KeyAlgorithm {
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::MlDsa44
                | KeyAlgorithm::MlDsa65
                | KeyAlgorithm::MlDsa87
                | KeyAlgorithm::EcdsaP256MlDsa65
                | KeyAlgorithm::Ed25519MlDsa65
        )
    }

    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::EcdsaP256MlDsa65 | KeyAlgorithm::Ed25519MlDsa65
        )
    }

    pub fn signature_algorithm(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => "SHA256withRSA",
            KeyAlgorithm::EcdsaP256 => "SHA256withECDSA",
            KeyAlgorithm::EcdsaP384 => "SHA384withECDSA",
            KeyAlgorithm::Ed25519 => "Ed25519",
            KeyAlgorithm::MlDsa44 => "ML-DSA-44",
            KeyAlgorithm::MlDsa65 => "ML-DSA-65",
            KeyAlgorithm::MlDsa87 => "ML-DSA-87",
            KeyAlgorithm::EcdsaP256MlDsa65 => "ECDSA-P256-ML-DSA-65",
            KeyAlgorithm::Ed25519MlDsa65 => "Ed25519-ML-DSA-65",
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa2048 => write!(f, "rsa-2048"),
            KeyAlgorithm::Rsa4096 => write!(f, "rsa-4096"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
            KeyAlgorithm::EcdsaP384 => write!(f, "ecdsa-p384"),
            KeyAlgorithm::Ed25519 => write!(f, "ed25519"),
            KeyAlgorithm::MlDsa44 => write!(f, "ml-dsa-44"),
            KeyAlgorithm::MlDsa65 => write!(f, "ml-dsa-65"),
            KeyAlgorithm::MlDsa87 => write!(f, "ml-dsa-87"),
            KeyAlgorithm::EcdsaP256MlDsa65 => write!(f, "hybrid-ecdsa-mldsa"),
            KeyAlgorithm::Ed25519MlDsa65 => write!(f, "hybrid-ed25519-mldsa"),
        }
    }
}

/// A key pair with public and private components
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub created_at: u64,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        let rng = SystemRandom::new();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match algorithm {
            KeyAlgorithm::EcdsaP256 => Self::generate_ecdsa_p256(&rng, created_at),
            KeyAlgorithm::EcdsaP384 => Self::generate_ecdsa_p384(&rng, created_at),
            KeyAlgorithm::Ed25519 => Self::generate_ed25519(&rng, created_at),
            KeyAlgorithm::MlDsa65 => Self::generate_ml_dsa_65(created_at),
            KeyAlgorithm::EcdsaP256MlDsa65 => Self::generate_hybrid_ecdsa_mldsa(&rng, created_at),
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Algorithm {:?} not yet implemented",
                algorithm
            ))),
        }
    }

    fn generate_ecdsa_p256(rng: &SystemRandom, created_at: u64) -> Result<Self> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            rng,
        )
        .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
        )
        .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: key_pair.public_key().as_ref().to_vec(),
            private_key: pkcs8.as_ref().to_vec(),
            created_at,
        })
    }

    fn generate_ecdsa_p384(rng: &SystemRandom, created_at: u64) -> Result<Self> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            rng,
        )
        .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            pkcs8.as_ref(),
        )
        .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP384,
            public_key: key_pair.public_key().as_ref().to_vec(),
            private_key: pkcs8.as_ref().to_vec(),
            created_at,
        })
    }

    fn generate_ed25519(rng: &SystemRandom, created_at: u64) -> Result<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        Ok(Self {
            algorithm: KeyAlgorithm::Ed25519,
            public_key: key_pair.public_key().as_ref().to_vec(),
            private_key: pkcs8.as_ref().to_vec(),
            created_at,
        })
    }

    fn generate_ml_dsa_65(created_at: u64) -> Result<Self> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::*;

        let (pk, sk) = dilithium3::keypair();

        Ok(Self {
            algorithm: KeyAlgorithm::MlDsa65,
            public_key: pk.as_bytes().to_vec(),
            private_key: sk.as_bytes().to_vec(),
            created_at,
        })
    }

    fn generate_hybrid_ecdsa_mldsa(rng: &SystemRandom, created_at: u64) -> Result<Self> {
        let classical = Self::generate_ecdsa_p256(rng, created_at)?;
        let pqc = Self::generate_ml_dsa_65(created_at)?;

        // Encode hybrid key pair
        let mut public_key = Vec::new();
        public_key.extend_from_slice(&(classical.public_key.len() as u32).to_be_bytes());
        public_key.extend_from_slice(&classical.public_key);
        public_key.extend_from_slice(&(pqc.public_key.len() as u32).to_be_bytes());
        public_key.extend_from_slice(&pqc.public_key);

        let mut private_key = Vec::new();
        private_key.extend_from_slice(&(classical.private_key.len() as u32).to_be_bytes());
        private_key.extend_from_slice(&classical.private_key);
        private_key.extend_from_slice(&(pqc.private_key.len() as u32).to_be_bytes());
        private_key.extend_from_slice(&pqc.private_key);

        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP256MlDsa65,
            public_key,
            private_key,
            created_at,
        })
    }

    /// Convert public key to PEM format
    pub fn public_key_pem(&self) -> String {
        let encoded = pem::encode(&pem::Pem::new("PUBLIC KEY", self.public_key.clone()));
        encoded
    }

    /// Get key size in bits
    pub fn key_size(&self) -> usize {
        match self.algorithm {
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::EcdsaP256 => 256,
            KeyAlgorithm::EcdsaP384 => 384,
            KeyAlgorithm::Ed25519 => 256,
            KeyAlgorithm::MlDsa44 => 1312 * 8, // Public key size
            KeyAlgorithm::MlDsa65 => 1952 * 8,
            KeyAlgorithm::MlDsa87 => 2592 * 8,
            KeyAlgorithm::EcdsaP256MlDsa65 => 256 + 1952 * 8,
            KeyAlgorithm::Ed25519MlDsa65 => 256 + 1952 * 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ecdsa_p256() {
        let kp = KeyPair::generate(KeyAlgorithm::EcdsaP256).unwrap();
        assert_eq!(kp.algorithm, KeyAlgorithm::EcdsaP256);
        assert!(!kp.public_key.is_empty());
        assert!(!kp.private_key.is_empty());
    }

    #[test]
    fn test_generate_ed25519() {
        let kp = KeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        assert_eq!(kp.algorithm, KeyAlgorithm::Ed25519);
        assert!(!kp.public_key.is_empty());
    }

    #[test]
    fn test_generate_ml_dsa_65() {
        let kp = KeyPair::generate(KeyAlgorithm::MlDsa65).unwrap();
        assert_eq!(kp.algorithm, KeyAlgorithm::MlDsa65);
        assert!(kp.algorithm.is_post_quantum());
    }

    #[test]
    fn test_generate_hybrid() {
        let kp = KeyPair::generate(KeyAlgorithm::EcdsaP256MlDsa65).unwrap();
        assert_eq!(kp.algorithm, KeyAlgorithm::EcdsaP256MlDsa65);
        assert!(kp.algorithm.is_hybrid());
    }
}
