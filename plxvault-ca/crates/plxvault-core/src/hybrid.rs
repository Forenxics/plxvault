//! Hybrid cryptography (classical + post-quantum)
//!
//! Combines classical algorithms (ECDSA, Ed25519) with post-quantum
//! algorithms (ML-DSA) for defense-in-depth during the transition period.

use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as RingKeyPair};
use ring::rand::SystemRandom;

use crate::error::{Error, Result};
use crate::pqc::{MlDsaKeyPair, MlDsaLevel};

#[derive(Debug, Clone, Copy)]
pub enum HybridScheme {
    EcdsaP256MlDsa65,
    Ed25519MlDsa65,
}

pub struct HybridKeyPair {
    pub scheme: HybridScheme,
    pub classical_public: Vec<u8>,
    pub classical_private: Vec<u8>,
    pub pqc_public: Vec<u8>,
    pub pqc_private: Vec<u8>,
}

impl HybridKeyPair {
    pub fn generate(scheme: HybridScheme) -> Result<Self> {
        let rng = SystemRandom::new();

        match scheme {
            HybridScheme::EcdsaP256MlDsa65 => {
                // Generate ECDSA P-256 key
                let ecdsa_pkcs8 = EcdsaKeyPair::generate_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &rng,
                )
                .map_err(|e| Error::KeyGeneration(e.to_string()))?;

                let ecdsa_kp = EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ecdsa_pkcs8.as_ref(),
                )
                .map_err(|e| Error::KeyGeneration(e.to_string()))?;

                // Generate ML-DSA-65 key
                let mldsa_kp = MlDsaKeyPair::generate(MlDsaLevel::MlDsa65)?;

                Ok(Self {
                    scheme,
                    classical_public: ecdsa_kp.public_key().as_ref().to_vec(),
                    classical_private: ecdsa_pkcs8.as_ref().to_vec(),
                    pqc_public: mldsa_kp.public_key,
                    pqc_private: mldsa_kp.secret_key,
                })
            }
            HybridScheme::Ed25519MlDsa65 => {
                // Generate Ed25519 key
                let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|e| Error::KeyGeneration(e.to_string()))?;

                let ed_kp = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref())
                    .map_err(|e| Error::KeyGeneration(e.to_string()))?;

                // Generate ML-DSA-65 key
                let mldsa_kp = MlDsaKeyPair::generate(MlDsaLevel::MlDsa65)?;

                Ok(Self {
                    scheme,
                    classical_public: ed_kp.public_key().as_ref().to_vec(),
                    classical_private: ed_pkcs8.as_ref().to_vec(),
                    pqc_public: mldsa_kp.public_key,
                    pqc_private: mldsa_kp.secret_key,
                })
            }
        }
    }

    /// Sign a message with both algorithms
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let classical_sig = self.sign_classical(message)?;
        let pqc_sig = self.sign_pqc(message)?;

        Ok(HybridSignature {
            scheme: self.scheme,
            classical: classical_sig,
            pqc: pqc_sig,
        })
    }

    fn sign_classical(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        match self.scheme {
            HybridScheme::EcdsaP256MlDsa65 => {
                let kp = EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &self.classical_private,
                )
                .map_err(|e| Error::Signing(e.to_string()))?;

                let sig = kp
                    .sign(&rng, message)
                    .map_err(|e| Error::Signing(e.to_string()))?;

                Ok(sig.as_ref().to_vec())
            }
            HybridScheme::Ed25519MlDsa65 => {
                let kp = Ed25519KeyPair::from_pkcs8(&self.classical_private)
                    .map_err(|e| Error::Signing(e.to_string()))?;

                let sig = kp.sign(message);
                Ok(sig.as_ref().to_vec())
            }
        }
    }

    fn sign_pqc(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mldsa_kp = MlDsaKeyPair {
            level: MlDsaLevel::MlDsa65,
            public_key: self.pqc_public.clone(),
            secret_key: self.pqc_private.clone(),
        };

        mldsa_kp.sign(message)
    }

    /// Verify requires EITHER signature to be valid (OR logic for compatibility)
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<HybridVerifyResult> {
        let classical_valid = self.verify_classical(message, &signature.classical)?;
        let pqc_valid = self.verify_pqc(message, &signature.pqc)?;

        Ok(HybridVerifyResult {
            classical_valid,
            pqc_valid,
            overall_valid: classical_valid || pqc_valid,
        })
    }

    fn verify_classical(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self.scheme {
            HybridScheme::EcdsaP256MlDsa65 => {
                use ring::signature::UnparsedPublicKey;
                let public_key = UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &self.classical_public,
                );
                Ok(public_key.verify(message, signature).is_ok())
            }
            HybridScheme::Ed25519MlDsa65 => {
                use ring::signature::UnparsedPublicKey;
                let public_key =
                    UnparsedPublicKey::new(&signature::ED25519, &self.classical_public);
                Ok(public_key.verify(message, signature).is_ok())
            }
        }
    }

    fn verify_pqc(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let mldsa_kp = MlDsaKeyPair {
            level: MlDsaLevel::MlDsa65,
            public_key: self.pqc_public.clone(),
            secret_key: Vec::new(), // Not needed for verify
        };

        mldsa_kp.verify(message, signature)
    }

    /// Encode combined public key
    pub fn encoded_public_key(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(self.classical_public.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.classical_public);
        encoded.extend_from_slice(&(self.pqc_public.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.pqc_public);
        encoded
    }
}

#[derive(Debug, Clone)]
pub struct HybridSignature {
    pub scheme: HybridScheme,
    pub classical: Vec<u8>,
    pub pqc: Vec<u8>,
}

impl HybridSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(self.classical.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.classical);
        encoded.extend_from_slice(&(self.pqc.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.pqc);
        encoded
    }
}

#[derive(Debug, Clone)]
pub struct HybridVerifyResult {
    pub classical_valid: bool,
    pub pqc_valid: bool,
    pub overall_valid: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_ecdsa_mldsa() {
        let kp = HybridKeyPair::generate(HybridScheme::EcdsaP256MlDsa65).unwrap();
        let message = b"Hybrid signature test";

        let signature = kp.sign(message).unwrap();
        let result = kp.verify(message, &signature).unwrap();

        assert!(result.classical_valid);
        assert!(result.pqc_valid);
        assert!(result.overall_valid);
    }

    #[test]
    fn test_hybrid_ed25519_mldsa() {
        let kp = HybridKeyPair::generate(HybridScheme::Ed25519MlDsa65).unwrap();
        let message = b"Ed25519 + ML-DSA hybrid test";

        let signature = kp.sign(message).unwrap();
        let result = kp.verify(message, &signature).unwrap();

        assert!(result.classical_valid);
        assert!(result.pqc_valid);
        assert!(result.overall_valid);
    }
}
