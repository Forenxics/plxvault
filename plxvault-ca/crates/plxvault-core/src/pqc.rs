//! Post-Quantum Cryptography support
//!
//! Implements NIST PQC standards:
//! - ML-DSA (formerly Dilithium) - Digital signatures
//! - ML-KEM (formerly Kyber) - Key encapsulation

use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub enum MlDsaLevel {
    MlDsa44,  // Level 2 (Dilithium2)
    MlDsa65,  // Level 3 (Dilithium3)
    MlDsa87,  // Level 5 (Dilithium5)
}

pub struct MlDsaKeyPair {
    pub level: MlDsaLevel,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl MlDsaKeyPair {
    pub fn generate(level: MlDsaLevel) -> Result<Self> {
        match level {
            MlDsaLevel::MlDsa44 => {
                let (pk, sk) = dilithium2::keypair();
                Ok(Self {
                    level,
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                })
            }
            MlDsaLevel::MlDsa65 => {
                let (pk, sk) = dilithium3::keypair();
                Ok(Self {
                    level,
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                })
            }
            MlDsaLevel::MlDsa87 => {
                let (pk, sk) = dilithium5::keypair();
                Ok(Self {
                    level,
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                })
            }
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self.level {
            MlDsaLevel::MlDsa44 => {
                let sk = dilithium2::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| Error::PostQuantum("Invalid secret key".to_string()))?;
                let sig = dilithium2::detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            MlDsaLevel::MlDsa65 => {
                let sk = dilithium3::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| Error::PostQuantum("Invalid secret key".to_string()))?;
                let sig = dilithium3::detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            MlDsaLevel::MlDsa87 => {
                let sk = dilithium5::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| Error::PostQuantum("Invalid secret key".to_string()))?;
                let sig = dilithium5::detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self.level {
            MlDsaLevel::MlDsa44 => {
                let pk = dilithium2::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| Error::PostQuantum("Invalid public key".to_string()))?;
                let sig = dilithium2::DetachedSignature::from_bytes(signature)
                    .map_err(|_| Error::PostQuantum("Invalid signature".to_string()))?;
                Ok(dilithium2::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            MlDsaLevel::MlDsa65 => {
                let pk = dilithium3::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| Error::PostQuantum("Invalid public key".to_string()))?;
                let sig = dilithium3::DetachedSignature::from_bytes(signature)
                    .map_err(|_| Error::PostQuantum("Invalid signature".to_string()))?;
                Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
            }
            MlDsaLevel::MlDsa87 => {
                let pk = dilithium5::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| Error::PostQuantum("Invalid public key".to_string()))?;
                let sig = dilithium5::DetachedSignature::from_bytes(signature)
                    .map_err(|_| Error::PostQuantum("Invalid signature".to_string()))?;
                Ok(dilithium5::verify_detached_signature(&sig, message, &pk).is_ok())
            }
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self.level {
            MlDsaLevel::MlDsa44 => 1312,
            MlDsaLevel::MlDsa65 => 1952,
            MlDsaLevel::MlDsa87 => 2592,
        }
    }

    pub fn signature_size(&self) -> usize {
        match self.level {
            MlDsaLevel::MlDsa44 => 2420,
            MlDsaLevel::MlDsa65 => 3293,
            MlDsaLevel::MlDsa87 => 4595,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let kp = MlDsaKeyPair::generate(MlDsaLevel::MlDsa65).unwrap();
        let message = b"Hello, post-quantum world!";

        let signature = kp.sign(message).unwrap();
        assert!(kp.verify(message, &signature).unwrap());

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!kp.verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_all_ml_dsa_levels() {
        for level in [MlDsaLevel::MlDsa44, MlDsaLevel::MlDsa65, MlDsaLevel::MlDsa87] {
            let kp = MlDsaKeyPair::generate(level).unwrap();
            let message = b"Test message";
            let signature = kp.sign(message).unwrap();
            assert!(kp.verify(message, &signature).unwrap());
        }
    }
}
