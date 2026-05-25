# PlxVault CA - Technical Specification

## AI-Native, Post-Quantum Ready Certificate Authority

**Version:** 1.0.0-draft
**Date:** 2026-05-25
**Status:** Specification

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Component Specifications](#3-component-specifications)
4. [Rust Crypto Core](#4-rust-crypto-core)
5. [Python API Layer](#5-python-api-layer)
6. [MCP Integration](#6-mcp-integration)
7. [Data Models](#7-data-models)
8. [Database Schema](#8-database-schema)
9. [Event System](#9-event-system)
10. [Security Model](#10-security-model)
11. [API Specification](#11-api-specification)
12. [Deployment](#12-deployment)
13. [Roadmap](#13-roadmap)

---

## 1. Executive Summary

PlxVault is a next-generation Certificate Authority designed for:

- **AI-Native**: MCP-first design, natural language operations
- **Post-Quantum Ready**: Hybrid classical/PQC cryptography
- **High Performance**: Rust crypto core, 10,000+ ops/sec
- **Developer Friendly**: Python API, REST/gRPC interfaces
- **Cloud Native**: Kubernetes, multi-region, edge-deployable
- **Zero Trust**: Short-lived certs, continuous verification

### Design Principles

1. **Security First**: Memory-safe crypto, auditable code
2. **API First**: Every operation accessible programmatically
3. **AI Accessible**: Natural language interface via MCP
4. **Future Proof**: PQC ready, extensible architecture
5. **Simple Core**: Complex features built on simple primitives

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENTS                                        │
├─────────────────────────────────────────────────────────────────────────┤
│  AI Agents    │  REST API    │  gRPC    │  ACME    │  CLI    │  Web UI │
│  (MCP)        │  Clients     │  Clients │  Clients │         │         │
└───────┬───────┴──────┬───────┴────┬─────┴────┬─────┴────┬────┴────┬────┘
        │              │            │          │          │         │
        ▼              ▼            ▼          ▼          ▼         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        PYTHON API LAYER                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ FastAPI  │ │ gRPC     │ │ MCP      │ │ ACME     │ │ Event    │      │
│  │ Server   │ │ Server   │ │ Server   │ │ Server   │ │ Handler  │      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
│       │            │            │            │            │             │
│  ┌────┴────────────┴────────────┴────────────┴────────────┴────┐       │
│  │                    Service Layer                             │       │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │       │
│  │  │ Certificate │ │ CA          │ │ End Entity  │            │       │
│  │  │ Service     │ │ Service     │ │ Service     │            │       │
│  │  └─────────────┘ └─────────────┘ └─────────────┘            │       │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │       │
│  │  │ Policy      │ │ Audit       │ │ Scheduler   │            │       │
│  │  │ Engine      │ │ Service     │ │ Service     │            │       │
│  │  └─────────────┘ └─────────────┘ └─────────────┘            │       │
│  └──────────────────────────┬───────────────────────────────────┘       │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                              ▼ PyO3 FFI
┌─────────────────────────────────────────────────────────────────────────┐
│                        RUST CRYPTO CORE                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │ Key          │ │ Certificate  │ │ CRL/OCSP     │ │ HSM          │   │
│  │ Generation   │ │ Signing      │ │ Generation   │ │ Interface    │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │ Classical    │ │ Post-Quantum │ │ Hybrid       │ │ Random       │   │
│  │ Algorithms   │ │ Algorithms   │ │ Schemes      │ │ Generation   │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA LAYER                                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │ PostgreSQL   │ │ Redis        │ │ S3/Minio     │ │ Vault/KMS    │   │
│  │ (Certs, EE)  │ │ (Cache,      │ │ (CRL, Audit) │ │ (Keys)       │   │
│  │              │ │  Events)     │ │              │ │              │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Specifications

### 3.1 Directory Structure

```
plxvault/
├── Cargo.toml                    # Rust workspace
├── pyproject.toml                # Python project
├── docker-compose.yml
├── Dockerfile
│
├── crates/                       # Rust crates
│   ├── plxvault-core/           # Core crypto operations
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── keys.rs          # Key generation
│   │       ├── certs.rs         # Certificate operations
│   │       ├── crl.rs           # CRL generation
│   │       ├── ocsp.rs          # OCSP responder
│   │       ├── pqc.rs           # Post-quantum crypto
│   │       ├── hybrid.rs        # Hybrid schemes
│   │       └── hsm.rs           # HSM interface
│   │
│   ├── plxvault-python/         # PyO3 bindings
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs           # Python module
│   │
│   └── plxvault-cli/            # Native CLI (optional)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
│
├── plxvault/                     # Python package
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py               # FastAPI application
│   │   ├── routes/
│   │   │   ├── certificates.py
│   │   │   ├── cas.py
│   │   │   ├── end_entities.py
│   │   │   ├── health.py
│   │   │   └── admin.py
│   │   └── middleware/
│   │       ├── auth.py
│   │       ├── audit.py
│   │       └── rate_limit.py
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── certificate.py
│   │   ├── ca.py
│   │   ├── end_entity.py
│   │   ├── policy.py
│   │   ├── audit.py
│   │   └── scheduler.py
│   │
│   ├── mcp/
│   │   ├── __init__.py
│   │   ├── server.py            # MCP server
│   │   └── tools.py             # Tool definitions
│   │
│   ├── acme/
│   │   ├── __init__.py
│   │   └── server.py            # ACME protocol
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── certificate.py
│   │   ├── ca.py
│   │   ├── end_entity.py
│   │   └── audit.py
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── connection.py
│   │   ├── repositories/
│   │   │   ├── certificate.py
│   │   │   ├── ca.py
│   │   │   └── end_entity.py
│   │   └── migrations/
│   │
│   ├── events/
│   │   ├── __init__.py
│   │   ├── bus.py
│   │   ├── handlers.py
│   │   └── webhooks.py
│   │
│   └── config/
│       ├── __init__.py
│       └── settings.py
│
├── tests/
│   ├── rust/
│   ├── python/
│   └── integration/
│
├── deploy/
│   ├── kubernetes/
│   │   ├── helm/
│   │   └── manifests/
│   └── docker/
│
└── docs/
    ├── api/
    ├── architecture/
    └── operations/
```

---

## 4. Rust Crypto Core

### 4.1 Core Library (plxvault-core)

```rust
// crates/plxvault-core/src/lib.rs

pub mod keys;
pub mod certs;
pub mod crl;
pub mod ocsp;
pub mod pqc;
pub mod hybrid;
pub mod hsm;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlxVaultError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Certificate signing failed: {0}")]
    Signing(String),
    
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    
    #[error("HSM error: {0}")]
    Hsm(String),
    
    #[error("PQC error: {0}")]
    PostQuantum(String),
}

pub type Result<T> = std::result::Result<T, PlxVaultError>;
```

### 4.2 Key Generation

```rust
// crates/plxvault-core/src/keys.rs

use ring::{rand, signature};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;

/// Supported key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    // Classical
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    
    // Post-Quantum (NIST standards)
    MlDsa44,      // Dilithium2 - NIST Level 2
    MlDsa65,      // Dilithium3 - NIST Level 3
    MlDsa87,      // Dilithium5 - NIST Level 5
    MlKem512,     // Kyber512
    MlKem768,     // Kyber768
    MlKem1024,    // Kyber1024
    SlhDsaShake128s,  // SPHINCS+
    
    // Hybrid (classical + PQC)
    EcdsaP256MlDsa65,
    Ed25519MlDsa65,
}

/// Key pair container
pub struct KeyPair {
    pub algorithm: KeyAlgorithm,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,  // Encrypted at rest
    pub created_at: u64,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        
        match algorithm {
            KeyAlgorithm::EcdsaP256 => Self::generate_ecdsa_p256(&rng),
            KeyAlgorithm::Ed25519 => Self::generate_ed25519(&rng),
            KeyAlgorithm::MlDsa65 => Self::generate_ml_dsa_65(),
            KeyAlgorithm::EcdsaP256MlDsa65 => Self::generate_hybrid_ecdsa_mldsa(&rng),
            // ... other algorithms
            _ => Err(PlxVaultError::KeyGeneration(
                format!("Algorithm {:?} not yet implemented", algorithm)
            )),
        }
    }
    
    fn generate_ecdsa_p256(rng: &rand::SystemRandom) -> Result<Self> {
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            rng,
        ).map_err(|e| PlxVaultError::KeyGeneration(e.to_string()))?;
        
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
        ).map_err(|e| PlxVaultError::KeyGeneration(e.to_string()))?;
        
        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: key_pair.public_key().as_ref().to_vec(),
            private_key: pkcs8.as_ref().to_vec(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    fn generate_ml_dsa_65() -> Result<Self> {
        let (pk, sk) = dilithium3::keypair();
        
        Ok(Self {
            algorithm: KeyAlgorithm::MlDsa65,
            public_key: pk.as_bytes().to_vec(),
            private_key: sk.as_bytes().to_vec(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    fn generate_hybrid_ecdsa_mldsa(rng: &rand::SystemRandom) -> Result<Self> {
        let classical = Self::generate_ecdsa_p256(rng)?;
        let pqc = Self::generate_ml_dsa_65()?;
        
        // Combine keys into hybrid structure
        let hybrid_public = HybridPublicKey {
            classical: classical.public_key,
            pqc: pqc.public_key,
        };
        
        let hybrid_private = HybridPrivateKey {
            classical: classical.private_key,
            pqc: pqc.private_key,
        };
        
        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP256MlDsa65,
            public_key: hybrid_public.encode(),
            private_key: hybrid_private.encode(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

#[derive(Debug)]
struct HybridPublicKey {
    classical: Vec<u8>,
    pqc: Vec<u8>,
}

impl HybridPublicKey {
    fn encode(&self) -> Vec<u8> {
        // ASN.1 SEQUENCE encoding
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(self.classical.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.classical);
        encoded.extend_from_slice(&(self.pqc.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.pqc);
        encoded
    }
}

#[derive(Debug)]
struct HybridPrivateKey {
    classical: Vec<u8>,
    pqc: Vec<u8>,
}

impl HybridPrivateKey {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(self.classical.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.classical);
        encoded.extend_from_slice(&(self.pqc.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.pqc);
        encoded
    }
}
```

### 4.3 Certificate Operations

```rust
// crates/plxvault-core/src/certs.rs

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType,
    IsCa, BasicConstraints, KeyUsagePurpose, SanType,
    SignatureAlgorithm, KeyPair as RcgenKeyPair,
};
use time::{Duration, OffsetDateTime};

/// Certificate request parameters
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub locality: Option<String>,
    pub state: Option<String>,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<String>,
    pub san_emails: Vec<String>,
    pub san_uris: Vec<String>,
    pub validity_days: u32,
    pub is_ca: bool,
    pub path_length: Option<u8>,
    pub key_usage: Vec<KeyUsage>,
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    CertSign,
    CrlSign,
}

#[derive(Debug, Clone, Copy)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

/// Issued certificate
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub serial_number: String,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub fingerprint_sha256: String,
    pub subject_dn: String,
    pub issuer_dn: String,
}

/// Certificate Authority
pub struct CertificateAuthority {
    certificate: Certificate,
    key_algorithm: KeyAlgorithm,
}

impl CertificateAuthority {
    /// Create a new root CA
    pub fn create_root(
        common_name: &str,
        algorithm: KeyAlgorithm,
        validity_years: u32,
    ) -> Result<(Self, IssuedCertificate)> {
        let mut params = CertificateParams::default();
        
        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        
        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(validity_years as i64 * 365);
        
        // CA constraints
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        
        // Generate key pair based on algorithm
        let key_pair = Self::generate_key_pair(algorithm)?;
        params.key_pair = Some(key_pair);
        
        // Self-sign
        let cert = Certificate::from_params(params)
            .map_err(|e| PlxVaultError::Signing(e.to_string()))?;
        
        let cert_pem = cert.serialize_pem()
            .map_err(|e| PlxVaultError::Signing(e.to_string()))?;
        
        let key_pem = cert.serialize_private_key_pem();
        
        let issued = IssuedCertificate {
            serial_number: hex::encode(cert.get_params().serial_number.as_ref().unwrap()),
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            not_before: cert.get_params().not_before.unix_timestamp() as u64,
            not_after: cert.get_params().not_after.unix_timestamp() as u64,
            fingerprint_sha256: Self::calculate_fingerprint(&cert)?,
            subject_dn: common_name.to_string(),
            issuer_dn: common_name.to_string(),
        };
        
        Ok((Self { certificate: cert, key_algorithm: algorithm }, issued))
    }
    
    /// Issue an end-entity certificate
    pub fn issue_certificate(&self, request: CertificateRequest) -> Result<IssuedCertificate> {
        let mut params = CertificateParams::default();
        
        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &request.common_name);
        if let Some(org) = &request.organization {
            dn.push(DnType::OrganizationName, org);
        }
        if let Some(ou) = &request.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        if let Some(country) = &request.country {
            dn.push(DnType::CountryName, country);
        }
        params.distinguished_name = dn;
        
        // Subject Alternative Names
        let mut sans = Vec::new();
        for dns in &request.san_dns {
            sans.push(SanType::DnsName(dns.clone()));
        }
        for ip in &request.san_ips {
            if let Ok(ip_addr) = ip.parse() {
                sans.push(SanType::IpAddress(ip_addr));
            }
        }
        for email in &request.san_emails {
            sans.push(SanType::Rfc822Name(email.clone()));
        }
        for uri in &request.san_uris {
            sans.push(SanType::URI(uri.clone()));
        }
        params.subject_alt_names = sans;
        
        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(request.validity_days as i64);
        
        // CA or end-entity
        if request.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(
                request.path_length.unwrap_or(0)
            ));
        } else {
            params.is_ca = IsCa::NoCa;
        }
        
        // Key usage
        params.key_usages = request.key_usage.iter().map(|ku| match ku {
            KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
            KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
            KeyUsage::KeyAgreement => KeyUsagePurpose::KeyAgreement,
            KeyUsage::CertSign => KeyUsagePurpose::KeyCertSign,
            KeyUsage::CrlSign => KeyUsagePurpose::CrlSign,
        }).collect();
        
        // Extended key usage
        params.extended_key_usages = request.extended_key_usage.iter().map(|eku| match eku {
            ExtendedKeyUsage::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsage::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsage::CodeSigning => rcgen::ExtendedKeyUsagePurpose::CodeSigning,
            ExtendedKeyUsage::EmailProtection => rcgen::ExtendedKeyUsagePurpose::EmailProtection,
            ExtendedKeyUsage::TimeStamping => rcgen::ExtendedKeyUsagePurpose::TimeStamping,
            ExtendedKeyUsage::OcspSigning => rcgen::ExtendedKeyUsagePurpose::OcspSigning,
        }).collect();
        
        // Generate key pair
        let key_pair = Self::generate_key_pair(self.key_algorithm)?;
        params.key_pair = Some(key_pair);
        
        // Create certificate
        let cert = Certificate::from_params(params)
            .map_err(|e| PlxVaultError::Signing(e.to_string()))?;
        
        // Sign with CA
        let cert_pem = cert.serialize_pem_with_signer(&self.certificate)
            .map_err(|e| PlxVaultError::Signing(e.to_string()))?;
        
        let key_pem = cert.serialize_private_key_pem();
        
        Ok(IssuedCertificate {
            serial_number: hex::encode(cert.get_params().serial_number.as_ref().unwrap()),
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            not_before: cert.get_params().not_before.unix_timestamp() as u64,
            not_after: cert.get_params().not_after.unix_timestamp() as u64,
            fingerprint_sha256: Self::calculate_fingerprint(&cert)?,
            subject_dn: request.common_name,
            issuer_dn: self.certificate.get_params()
                .distinguished_name
                .get(&DnType::CommonName)
                .map(|s| s.to_string())
                .unwrap_or_default(),
        })
    }
    
    /// Sign a CSR
    pub fn sign_csr(&self, csr_pem: &str, validity_days: u32) -> Result<IssuedCertificate> {
        // Parse CSR
        let csr = rcgen::CertificateSigningRequest::from_pem(csr_pem)
            .map_err(|e| PlxVaultError::InvalidCertificate(e.to_string()))?;
        
        // Set validity
        let params = csr.params();
        // ... sign with CA
        
        todo!("Implement CSR signing")
    }
    
    fn generate_key_pair(algorithm: KeyAlgorithm) -> Result<RcgenKeyPair> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => {
                RcgenKeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
                    .map_err(|e| PlxVaultError::KeyGeneration(e.to_string()))
            }
            KeyAlgorithm::Ed25519 => {
                RcgenKeyPair::generate(&rcgen::PKCS_ED25519)
                    .map_err(|e| PlxVaultError::KeyGeneration(e.to_string()))
            }
            _ => Err(PlxVaultError::KeyGeneration(
                format!("Algorithm {:?} not supported for certificate generation", algorithm)
            )),
        }
    }
    
    fn calculate_fingerprint(cert: &Certificate) -> Result<String> {
        use sha2::{Sha256, Digest};
        let der = cert.serialize_der()
            .map_err(|e| PlxVaultError::Signing(e.to_string()))?;
        let hash = Sha256::digest(&der);
        Ok(hex::encode(hash))
    }
}

/// Revocation entry
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_date: u64,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Copy)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
}
```

### 4.4 CRL and OCSP

```rust
// crates/plxvault-core/src/crl.rs

use x509_crl::{CertificateRevocationList, RevokedCert, TbsCertList};

pub struct CrlGenerator {
    ca: CertificateAuthority,
    revoked: Vec<RevokedCertificate>,
}

impl CrlGenerator {
    pub fn new(ca: CertificateAuthority) -> Self {
        Self {
            ca,
            revoked: Vec::new(),
        }
    }
    
    pub fn add_revoked(&mut self, cert: RevokedCertificate) {
        self.revoked.push(cert);
    }
    
    pub fn generate(&self, validity_days: u32) -> Result<Vec<u8>> {
        // Generate CRL signed by CA
        todo!("Implement CRL generation")
    }
}

// crates/plxvault-core/src/ocsp.rs

pub struct OcspResponder {
    ca: CertificateAuthority,
    revoked_serials: std::collections::HashSet<String>,
}

impl OcspResponder {
    pub fn new(ca: CertificateAuthority) -> Self {
        Self {
            ca,
            revoked_serials: std::collections::HashSet::new(),
        }
    }
    
    pub fn check_status(&self, serial: &str) -> CertificateStatus {
        if self.revoked_serials.contains(serial) {
            CertificateStatus::Revoked
        } else {
            CertificateStatus::Good
        }
    }
    
    pub fn respond(&self, request: &[u8]) -> Result<Vec<u8>> {
        // Parse OCSP request and generate signed response
        todo!("Implement OCSP response")
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CertificateStatus {
    Good,
    Revoked,
    Unknown,
}
```

### 4.5 PyO3 Python Bindings

```rust
// crates/plxvault-python/src/lib.rs

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use plxvault_core::{
    keys::{KeyPair, KeyAlgorithm},
    certs::{CertificateAuthority, CertificateRequest, IssuedCertificate},
};

#[pyclass]
#[derive(Clone)]
struct PyKeyAlgorithm(KeyAlgorithm);

#[pymethods]
impl PyKeyAlgorithm {
    #[staticmethod]
    fn ecdsa_p256() -> Self {
        Self(KeyAlgorithm::EcdsaP256)
    }
    
    #[staticmethod]
    fn ed25519() -> Self {
        Self(KeyAlgorithm::Ed25519)
    }
    
    #[staticmethod]
    fn ml_dsa_65() -> Self {
        Self(KeyAlgorithm::MlDsa65)
    }
    
    #[staticmethod]
    fn hybrid_ecdsa_mldsa() -> Self {
        Self(KeyAlgorithm::EcdsaP256MlDsa65)
    }
}

#[pyclass]
struct PyKeyPair {
    inner: KeyPair,
}

#[pymethods]
impl PyKeyPair {
    #[staticmethod]
    fn generate(algorithm: PyKeyAlgorithm) -> PyResult<Self> {
        KeyPair::generate(algorithm.0)
            .map(|kp| Self { inner: kp })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
    
    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.clone()
    }
    
    #[getter]
    fn public_key_pem(&self) -> PyResult<String> {
        // Convert to PEM format
        todo!()
    }
}

#[pyclass]
struct PyCertificateAuthority {
    inner: CertificateAuthority,
}

#[pymethods]
impl PyCertificateAuthority {
    #[staticmethod]
    fn create_root(
        common_name: &str,
        algorithm: PyKeyAlgorithm,
        validity_years: u32,
    ) -> PyResult<(Self, PyIssuedCertificate)> {
        CertificateAuthority::create_root(common_name, algorithm.0, validity_years)
            .map(|(ca, cert)| (
                Self { inner: ca },
                PyIssuedCertificate { inner: cert },
            ))
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
    
    fn issue_certificate(
        &self,
        common_name: &str,
        validity_days: u32,
        san_dns: Option<Vec<String>>,
        san_ips: Option<Vec<String>>,
        is_ca: Option<bool>,
    ) -> PyResult<PyIssuedCertificate> {
        let request = CertificateRequest {
            common_name: common_name.to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            locality: None,
            state: None,
            san_dns: san_dns.unwrap_or_default(),
            san_ips: san_ips.unwrap_or_default(),
            san_emails: Vec::new(),
            san_uris: Vec::new(),
            validity_days,
            is_ca: is_ca.unwrap_or(false),
            path_length: None,
            key_usage: vec![
                plxvault_core::certs::KeyUsage::DigitalSignature,
                plxvault_core::certs::KeyUsage::KeyEncipherment,
            ],
            extended_key_usage: vec![
                plxvault_core::certs::ExtendedKeyUsage::ServerAuth,
                plxvault_core::certs::ExtendedKeyUsage::ClientAuth,
            ],
        };
        
        self.inner.issue_certificate(request)
            .map(|cert| PyIssuedCertificate { inner: cert })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
    
    fn sign_csr(&self, csr_pem: &str, validity_days: u32) -> PyResult<PyIssuedCertificate> {
        self.inner.sign_csr(csr_pem, validity_days)
            .map(|cert| PyIssuedCertificate { inner: cert })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

#[pyclass]
#[derive(Clone)]
struct PyIssuedCertificate {
    inner: IssuedCertificate,
}

#[pymethods]
impl PyIssuedCertificate {
    #[getter]
    fn serial_number(&self) -> &str {
        &self.inner.serial_number
    }
    
    #[getter]
    fn certificate_pem(&self) -> &str {
        &self.inner.certificate_pem
    }
    
    #[getter]
    fn private_key_pem(&self) -> Option<&str> {
        self.inner.private_key_pem.as_deref()
    }
    
    #[getter]
    fn not_before(&self) -> u64 {
        self.inner.not_before
    }
    
    #[getter]
    fn not_after(&self) -> u64 {
        self.inner.not_after
    }
    
    #[getter]
    fn fingerprint_sha256(&self) -> &str {
        &self.inner.fingerprint_sha256
    }
    
    #[getter]
    fn subject_dn(&self) -> &str {
        &self.inner.subject_dn
    }
    
    #[getter]
    fn issuer_dn(&self) -> &str {
        &self.inner.issuer_dn
    }
}

/// Python module
#[pymodule]
fn plxvault_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeyAlgorithm>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyCertificateAuthority>()?;
    m.add_class::<PyIssuedCertificate>()?;
    Ok(())
}
```

---

## 5. Python API Layer

### 5.1 FastAPI Application

```python
# plxvault/api/app.py

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog

from plxvault.config import settings
from plxvault.db import init_db, close_db
from plxvault.events import EventBus
from plxvault.api.routes import certificates, cas, end_entities, health, admin
from plxvault.api.middleware import AuditMiddleware, RateLimitMiddleware

logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting PlxVault CA")
    await init_db()
    app.state.event_bus = EventBus()
    await app.state.event_bus.connect()
    yield
    # Shutdown
    logger.info("Shutting down PlxVault CA")
    await app.state.event_bus.disconnect()
    await close_db()

app = FastAPI(
    title="PlxVault CA",
    description="AI-Native, Post-Quantum Ready Certificate Authority",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)

# Routes
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(certificates.router, prefix="/api/v1/certificates", tags=["Certificates"])
app.include_router(cas.router, prefix="/api/v1/cas", tags=["Certificate Authorities"])
app.include_router(end_entities.router, prefix="/api/v1/entities", tags=["End Entities"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Administration"])

# ACME endpoints (RFC 8555)
from plxvault.acme import acme_router
app.include_router(acme_router, prefix="/acme", tags=["ACME"])
```

### 5.2 Certificate Routes

```python
# plxvault/api/routes/certificates.py

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

from plxvault.services.certificate import CertificateService
from plxvault.models.certificate import Certificate, CertificateStatus
from plxvault.api.deps import get_certificate_service, get_current_user

router = APIRouter()

class KeyAlgorithm(str, Enum):
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"
    HYBRID_ECDSA_MLDSA = "hybrid-ecdsa-mldsa"

class CertificateType(str, Enum):
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code-signing"
    EMAIL = "email"
    CA = "ca"

class IssueCertificateRequest(BaseModel):
    common_name: str = Field(..., min_length=1, max_length=255)
    certificate_type: CertificateType = CertificateType.SERVER
    san_dns: List[str] = Field(default_factory=list)
    san_ips: List[str] = Field(default_factory=list)
    san_emails: List[str] = Field(default_factory=list)
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = Field(None, min_length=2, max_length=2)
    validity_days: int = Field(365, ge=1, le=3650)
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ECDSA_P256
    ca_name: Optional[str] = None
    csr: Optional[str] = None  # PEM-encoded CSR

class IssueCertificateResponse(BaseModel):
    id: str
    serial_number: str
    common_name: str
    certificate_pem: str
    private_key_pem: Optional[str] = None
    chain_pem: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    issuer_dn: str
    subject_dn: str

class CertificateResponse(BaseModel):
    id: str
    serial_number: str
    common_name: str
    status: CertificateStatus
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    issuer_dn: str
    subject_dn: str
    revocation_date: Optional[datetime] = None
    revocation_reason: Optional[str] = None

class RevocationReason(str, Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key-compromise"
    CA_COMPROMISE = "ca-compromise"
    AFFILIATION_CHANGED = "affiliation-changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation-of-operation"

class RevokeCertificateRequest(BaseModel):
    reason: RevocationReason = RevocationReason.UNSPECIFIED
    invalidity_date: Optional[datetime] = None

@router.post("", response_model=IssueCertificateResponse)
async def issue_certificate(
    request: IssueCertificateRequest,
    background_tasks: BackgroundTasks,
    service: CertificateService = Depends(get_certificate_service),
    user = Depends(get_current_user),
):
    """Issue a new certificate."""
    cert = await service.issue(
        common_name=request.common_name,
        certificate_type=request.certificate_type,
        san_dns=request.san_dns,
        san_ips=request.san_ips,
        san_emails=request.san_emails,
        organization=request.organization,
        organizational_unit=request.organizational_unit,
        country=request.country,
        validity_days=request.validity_days,
        key_algorithm=request.key_algorithm,
        ca_name=request.ca_name,
        csr=request.csr,
        issued_by=user.id,
    )
    
    # Emit event in background
    background_tasks.add_task(
        service.emit_event,
        "certificate.issued",
        {"certificate_id": cert.id, "common_name": cert.common_name}
    )
    
    return cert

@router.get("", response_model=List[CertificateResponse])
async def list_certificates(
    status: Optional[CertificateStatus] = None,
    common_name: Optional[str] = None,
    issuer: Optional[str] = None,
    expiring_within_days: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: CertificateService = Depends(get_certificate_service),
):
    """List certificates with optional filters."""
    return await service.list(
        status=status,
        common_name=common_name,
        issuer=issuer,
        expiring_within_days=expiring_within_days,
        limit=limit,
        offset=offset,
    )

@router.get("/expiring", response_model=List[CertificateResponse])
async def get_expiring_certificates(
    days: int = Query(30, ge=1, le=365),
    ca_name: Optional[str] = None,
    service: CertificateService = Depends(get_certificate_service),
):
    """Get certificates expiring within specified days."""
    return await service.get_expiring(days=days, ca_name=ca_name)

@router.get("/{certificate_id}", response_model=CertificateResponse)
async def get_certificate(
    certificate_id: str,
    include_pem: bool = Query(False),
    service: CertificateService = Depends(get_certificate_service),
):
    """Get certificate details."""
    cert = await service.get(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert

@router.get("/{certificate_id}/download")
async def download_certificate(
    certificate_id: str,
    format: str = Query("pem", regex="^(pem|der|pkcs12|pkcs7)$"),
    include_chain: bool = Query(True),
    include_key: bool = Query(False),
    password: Optional[str] = None,  # For PKCS12
    service: CertificateService = Depends(get_certificate_service),
):
    """Download certificate in specified format."""
    return await service.download(
        certificate_id=certificate_id,
        format=format,
        include_chain=include_chain,
        include_key=include_key,
        password=password,
    )

@router.post("/{certificate_id}/revoke")
async def revoke_certificate(
    certificate_id: str,
    request: RevokeCertificateRequest,
    background_tasks: BackgroundTasks,
    service: CertificateService = Depends(get_certificate_service),
    user = Depends(get_current_user),
):
    """Revoke a certificate."""
    cert = await service.revoke(
        certificate_id=certificate_id,
        reason=request.reason,
        invalidity_date=request.invalidity_date,
        revoked_by=user.id,
    )
    
    background_tasks.add_task(
        service.emit_event,
        "certificate.revoked",
        {"certificate_id": cert.id, "reason": request.reason}
    )
    
    return {"status": "revoked", "certificate_id": cert.id}

@router.post("/{certificate_id}/renew", response_model=IssueCertificateResponse)
async def renew_certificate(
    certificate_id: str,
    validity_days: int = Query(365, ge=1, le=3650),
    new_key: bool = Query(True),
    service: CertificateService = Depends(get_certificate_service),
    user = Depends(get_current_user),
):
    """Renew a certificate."""
    return await service.renew(
        certificate_id=certificate_id,
        validity_days=validity_days,
        new_key=new_key,
        renewed_by=user.id,
    )

# Bulk operations
class BulkIssueRequest(BaseModel):
    certificates: List[IssueCertificateRequest]
    
class BulkIssueResponse(BaseModel):
    issued: List[IssueCertificateResponse]
    failed: List[dict]

@router.post("/bulk/issue", response_model=BulkIssueResponse)
async def bulk_issue_certificates(
    request: BulkIssueRequest,
    service: CertificateService = Depends(get_certificate_service),
    user = Depends(get_current_user),
):
    """Issue multiple certificates in one request."""
    return await service.bulk_issue(request.certificates, issued_by=user.id)

class BulkRevokeRequest(BaseModel):
    certificate_ids: List[str]
    reason: RevocationReason = RevocationReason.UNSPECIFIED

@router.post("/bulk/revoke")
async def bulk_revoke_certificates(
    request: BulkRevokeRequest,
    service: CertificateService = Depends(get_certificate_service),
    user = Depends(get_current_user),
):
    """Revoke multiple certificates in one request."""
    return await service.bulk_revoke(
        certificate_ids=request.certificate_ids,
        reason=request.reason,
        revoked_by=user.id,
    )
```

### 5.3 Certificate Service

```python
# plxvault/services/certificate.py

from typing import Optional, List
from datetime import datetime, timedelta
import structlog

from plxvault_core import CertificateAuthority, KeyAlgorithm as RustKeyAlgorithm
from plxvault.db.repositories.certificate import CertificateRepository
from plxvault.db.repositories.ca import CARepository
from plxvault.models.certificate import Certificate, CertificateStatus
from plxvault.events import EventBus
from plxvault.config import settings

logger = structlog.get_logger()

class CertificateService:
    def __init__(
        self,
        cert_repo: CertificateRepository,
        ca_repo: CARepository,
        event_bus: EventBus,
    ):
        self.cert_repo = cert_repo
        self.ca_repo = ca_repo
        self.event_bus = event_bus
        
    async def issue(
        self,
        common_name: str,
        certificate_type: str,
        san_dns: List[str],
        san_ips: List[str],
        san_emails: List[str],
        organization: Optional[str],
        organizational_unit: Optional[str],
        country: Optional[str],
        validity_days: int,
        key_algorithm: str,
        ca_name: Optional[str],
        csr: Optional[str],
        issued_by: str,
    ) -> Certificate:
        """Issue a new certificate."""
        
        # Get CA
        ca_name = ca_name or settings.default_ca
        ca = await self.ca_repo.get_by_name(ca_name)
        if not ca:
            raise ValueError(f"CA '{ca_name}' not found")
        
        # Load CA into Rust
        rust_ca = CertificateAuthority.from_pem(
            ca.certificate_pem,
            ca.private_key_pem,
        )
        
        # Map algorithm
        algo_map = {
            "ecdsa-p256": RustKeyAlgorithm.ecdsa_p256(),
            "ed25519": RustKeyAlgorithm.ed25519(),
            "ml-dsa-65": RustKeyAlgorithm.ml_dsa_65(),
            "hybrid-ecdsa-mldsa": RustKeyAlgorithm.hybrid_ecdsa_mldsa(),
        }
        rust_algo = algo_map.get(key_algorithm, RustKeyAlgorithm.ecdsa_p256())
        
        # Issue certificate via Rust core
        if csr:
            issued = rust_ca.sign_csr(csr, validity_days)
        else:
            issued = rust_ca.issue_certificate(
                common_name=common_name,
                validity_days=validity_days,
                san_dns=san_dns or None,
                san_ips=san_ips or None,
            )
        
        # Store in database
        cert = Certificate(
            serial_number=issued.serial_number,
            common_name=common_name,
            certificate_pem=issued.certificate_pem,
            private_key_pem=issued.private_key_pem,
            not_before=datetime.fromtimestamp(issued.not_before),
            not_after=datetime.fromtimestamp(issued.not_after),
            fingerprint_sha256=issued.fingerprint_sha256,
            subject_dn=issued.subject_dn,
            issuer_dn=issued.issuer_dn,
            issuer_ca_id=ca.id,
            status=CertificateStatus.ACTIVE,
            certificate_type=certificate_type,
            key_algorithm=key_algorithm,
            issued_by=issued_by,
        )
        
        await self.cert_repo.create(cert)
        
        logger.info(
            "Certificate issued",
            serial=cert.serial_number,
            cn=common_name,
            ca=ca_name,
        )
        
        return cert
    
    async def revoke(
        self,
        certificate_id: str,
        reason: str,
        invalidity_date: Optional[datetime],
        revoked_by: str,
    ) -> Certificate:
        """Revoke a certificate."""
        
        cert = await self.cert_repo.get(certificate_id)
        if not cert:
            raise ValueError("Certificate not found")
        
        if cert.status == CertificateStatus.REVOKED:
            raise ValueError("Certificate already revoked")
        
        cert.status = CertificateStatus.REVOKED
        cert.revocation_date = datetime.utcnow()
        cert.revocation_reason = reason
        cert.revoked_by = revoked_by
        
        await self.cert_repo.update(cert)
        
        # Trigger CRL regeneration
        await self.event_bus.publish(
            "certificate.revoked",
            {"certificate_id": cert.id, "ca_id": cert.issuer_ca_id}
        )
        
        logger.info(
            "Certificate revoked",
            serial=cert.serial_number,
            reason=reason,
        )
        
        return cert
    
    async def get_expiring(
        self,
        days: int,
        ca_name: Optional[str] = None,
    ) -> List[Certificate]:
        """Get certificates expiring within N days."""
        
        expiry_date = datetime.utcnow() + timedelta(days=days)
        return await self.cert_repo.get_expiring_before(
            expiry_date=expiry_date,
            ca_name=ca_name,
        )
    
    async def bulk_issue(
        self,
        requests: List[dict],
        issued_by: str,
    ) -> dict:
        """Issue multiple certificates."""
        
        issued = []
        failed = []
        
        for req in requests:
            try:
                cert = await self.issue(**req, issued_by=issued_by)
                issued.append(cert)
            except Exception as e:
                failed.append({
                    "common_name": req.get("common_name"),
                    "error": str(e),
                })
        
        return {"issued": issued, "failed": failed}
    
    async def emit_event(self, event_type: str, data: dict):
        """Emit event to event bus."""
        await self.event_bus.publish(event_type, data)
```

---

## 6. MCP Integration

### 6.1 MCP Server

```python
# plxvault/mcp/server.py

import json
import sys
import asyncio
from typing import Any

from plxvault.mcp.tools import TOOLS, handle_tool_call
from plxvault.services.certificate import CertificateService
from plxvault.db import get_session

JSONRPC_VERSION = "2.0"

class MCPServer:
    def __init__(self):
        self.initialized = False
        
    def send_response(self, id: Any, result: Any = None, error: Any = None):
        response = {"jsonrpc": JSONRPC_VERSION, "id": id}
        if error:
            response["error"] = error
        else:
            response["result"] = result
        print(json.dumps(response), flush=True)
    
    async def handle_request(self, request: dict):
        method = request.get("method")
        id = request.get("id")
        params = request.get("params", {})
        
        if method == "initialize":
            self.send_response(id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "plxvault-ca",
                    "version": "1.0.0",
                    "description": "AI-Native PKI - Issue, revoke, and manage certificates with natural language"
                }
            })
            
        elif method == "tools/list":
            self.send_response(id, {"tools": TOOLS})
            
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            try:
                result = await handle_tool_call(tool_name, arguments)
                self.send_response(id, {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]
                })
            except Exception as e:
                self.send_response(id, {
                    "content": [{"type": "text", "text": json.dumps({"error": str(e)})}]
                })
                
        elif method == "notifications/initialized":
            self.initialized = True
            
        else:
            self.send_response(id, error={"code": -32601, "message": f"Method not found: {method}"})
    
    async def run(self):
        loop = asyncio.get_event_loop()
        
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                await self.handle_request(request)
            except json.JSONDecodeError as e:
                self.send_response(None, error={"code": -32700, "message": f"Parse error: {e}"})

def main():
    server = MCPServer()
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
```

### 6.2 MCP Tools

```python
# plxvault/mcp/tools.py

from typing import Any
from datetime import datetime

from plxvault.services.certificate import CertificateService
from plxvault.services.ca import CAService
from plxvault.db import get_session

TOOLS = [
    {
        "name": "issue_certificate",
        "description": "Issue a new TLS/SSL certificate. Specify the hostname and optional parameters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": {
                    "type": "string",
                    "description": "Hostname or CN for the certificate (e.g., 'api.example.com')"
                },
                "type": {
                    "type": "string",
                    "enum": ["server", "client", "code-signing", "email"],
                    "description": "Certificate type",
                    "default": "server"
                },
                "san": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Subject Alternative Names (additional hostnames/IPs)"
                },
                "validity_days": {
                    "type": "integer",
                    "description": "Validity period in days",
                    "default": 365
                },
                "algorithm": {
                    "type": "string",
                    "enum": ["ecdsa-p256", "ed25519", "rsa-2048", "ml-dsa-65", "hybrid-ecdsa-mldsa"],
                    "description": "Key algorithm (use hybrid-ecdsa-mldsa for post-quantum)",
                    "default": "ecdsa-p256"
                }
            },
            "required": ["common_name"]
        }
    },
    {
        "name": "revoke_certificate",
        "description": "Revoke a certificate by serial number or common name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_number": {"type": "string"},
                "common_name": {"type": "string"},
                "reason": {
                    "type": "string",
                    "enum": ["unspecified", "key-compromise", "superseded", "cessation-of-operation"],
                    "default": "unspecified"
                }
            }
        }
    },
    {
        "name": "renew_certificate",
        "description": "Renew an existing certificate before it expires.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_number": {"type": "string"},
                "common_name": {"type": "string"},
                "validity_days": {"type": "integer", "default": 365}
            }
        }
    },
    {
        "name": "list_certificates",
        "description": "List certificates with optional filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["active", "revoked", "expired", "all"],
                    "default": "all"
                },
                "common_name": {"type": "string"},
                "expiring_within_days": {"type": "integer"},
                "limit": {"type": "integer", "default": 50}
            }
        }
    },
    {
        "name": "get_expiring_certificates",
        "description": "Get certificates expiring within N days. Critical for preventing outages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "default": 30}
            }
        }
    },
    {
        "name": "list_cas",
        "description": "List all Certificate Authorities.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "create_ca",
        "description": "Create a new Certificate Authority (root or intermediate).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "CA name"},
                "common_name": {"type": "string", "description": "CA common name"},
                "type": {
                    "type": "string",
                    "enum": ["root", "intermediate"],
                    "default": "root"
                },
                "parent_ca": {"type": "string", "description": "Parent CA name (for intermediate)"},
                "validity_years": {"type": "integer", "default": 10},
                "algorithm": {
                    "type": "string",
                    "enum": ["ecdsa-p256", "ecdsa-p384", "ed25519", "hybrid-ecdsa-mldsa"],
                    "default": "ecdsa-p384"
                }
            },
            "required": ["name", "common_name"]
        }
    },
    {
        "name": "bulk_issue",
        "description": "Issue certificates for multiple hosts at once.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hostnames to issue certs for"
                },
                "validity_days": {"type": "integer", "default": 365},
                "algorithm": {"type": "string", "default": "ecdsa-p256"}
            },
            "required": ["hosts"]
        }
    },
    {
        "name": "bulk_renew_expiring",
        "description": "Renew all certificates expiring within N days.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "default": 30},
                "dry_run": {
                    "type": "boolean",
                    "default": True,
                    "description": "If true, list what would be renewed without renewing"
                }
            }
        }
    },
    {
        "name": "health_check",
        "description": "Check PlxVault CA system health.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "get_statistics",
        "description": "Get PKI statistics: total certs, by status, expiring soon, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

async def handle_tool_call(name: str, arguments: dict) -> dict:
    """Route tool calls to service methods."""
    
    async with get_session() as session:
        cert_service = CertificateService(session)
        ca_service = CAService(session)
        
        if name == "issue_certificate":
            cert = await cert_service.issue(
                common_name=arguments["common_name"],
                certificate_type=arguments.get("type", "server"),
                san_dns=arguments.get("san", []),
                validity_days=arguments.get("validity_days", 365),
                key_algorithm=arguments.get("algorithm", "ecdsa-p256"),
            )
            return {
                "success": True,
                "certificate": {
                    "serial_number": cert.serial_number,
                    "common_name": cert.common_name,
                    "not_after": cert.not_after.isoformat(),
                    "fingerprint": cert.fingerprint_sha256,
                }
            }
            
        elif name == "revoke_certificate":
            cert = await cert_service.revoke(
                serial_number=arguments.get("serial_number"),
                common_name=arguments.get("common_name"),
                reason=arguments.get("reason", "unspecified"),
            )
            return {"success": True, "revoked": cert.serial_number}
            
        elif name == "get_expiring_certificates":
            certs = await cert_service.get_expiring(
                days=arguments.get("days", 30)
            )
            return {
                "success": True,
                "count": len(certs),
                "certificates": [
                    {
                        "serial_number": c.serial_number,
                        "common_name": c.common_name,
                        "expires": c.not_after.isoformat(),
                        "days_until_expiry": (c.not_after - datetime.utcnow()).days,
                    }
                    for c in certs
                ]
            }
            
        elif name == "list_cas":
            cas = await ca_service.list()
            return {
                "success": True,
                "cas": [
                    {
                        "name": ca.name,
                        "common_name": ca.common_name,
                        "type": ca.ca_type,
                        "expires": ca.not_after.isoformat(),
                    }
                    for ca in cas
                ]
            }
            
        elif name == "health_check":
            return {
                "success": True,
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": datetime.utcnow().isoformat(),
            }
            
        elif name == "get_statistics":
            stats = await cert_service.get_statistics()
            return {"success": True, **stats}
            
        else:
            return {"error": f"Unknown tool: {name}"}
```

---

## 7. Data Models

```python
# plxvault/models/certificate.py

from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, Text, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import uuid

from plxvault.db.base import Base

class CertificateStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"

class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    serial_number = Column(String(64), unique=True, nullable=False, index=True)
    common_name = Column(String(255), nullable=False, index=True)
    
    # Certificate data
    certificate_pem = Column(Text, nullable=False)
    private_key_pem = Column(Text)  # Encrypted, nullable if CSR was used
    chain_pem = Column(Text)
    
    # Validity
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False, index=True)
    
    # Identifiers
    fingerprint_sha256 = Column(String(64), nullable=False, index=True)
    subject_dn = Column(String(500), nullable=False)
    issuer_dn = Column(String(500), nullable=False)
    
    # Metadata
    status = Column(Enum(CertificateStatus), default=CertificateStatus.ACTIVE, index=True)
    certificate_type = Column(String(50))  # server, client, code-signing, email
    key_algorithm = Column(String(50))
    key_size = Column(Integer)
    
    # Relationships
    issuer_ca_id = Column(String(36), ForeignKey("certificate_authorities.id"))
    issuer_ca = relationship("CertificateAuthority", back_populates="issued_certificates")
    
    # Revocation
    revocation_date = Column(DateTime)
    revocation_reason = Column(String(50))
    
    # Audit
    issued_by = Column(String(255))
    issued_at = Column(DateTime, default=datetime.utcnow)
    revoked_by = Column(String(255))
    
    # Custom metadata
    tags = Column(Text)  # JSON
    metadata = Column(Text)  # JSON

# plxvault/models/ca.py

class CAType(str, enum.Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    ISSUING = "issuing"

class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False)
    common_name = Column(String(255), nullable=False)
    
    # Certificate data
    certificate_pem = Column(Text, nullable=False)
    private_key_pem = Column(Text, nullable=False)  # Encrypted
    chain_pem = Column(Text)
    
    # Validity
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    
    # Type and hierarchy
    ca_type = Column(Enum(CAType), nullable=False)
    parent_ca_id = Column(String(36), ForeignKey("certificate_authorities.id"))
    parent_ca = relationship("CertificateAuthority", remote_side=[id])
    
    # Configuration
    key_algorithm = Column(String(50))
    max_path_length = Column(Integer)
    
    # Relationships
    issued_certificates = relationship("Certificate", back_populates="issuer_ca")
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Audit
    created_by = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
```

---

## 8. Database Schema

```sql
-- PostgreSQL schema

CREATE TABLE certificate_authorities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,  -- Encrypted with master key
    chain_pem TEXT,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    ca_type VARCHAR(20) NOT NULL,  -- root, intermediate, issuing
    parent_ca_id UUID REFERENCES certificate_authorities(id),
    key_algorithm VARCHAR(50),
    max_path_length INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT,  -- Encrypted, nullable
    chain_pem TEXT,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    fingerprint_sha256 VARCHAR(64) NOT NULL,
    subject_dn VARCHAR(500) NOT NULL,
    issuer_dn VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    certificate_type VARCHAR(50),
    key_algorithm VARCHAR(50),
    key_size INTEGER,
    issuer_ca_id UUID REFERENCES certificate_authorities(id),
    revocation_date TIMESTAMP,
    revocation_reason VARCHAR(50),
    issued_by VARCHAR(255),
    issued_at TIMESTAMP DEFAULT NOW(),
    revoked_by VARCHAR(255),
    tags JSONB,
    metadata JSONB
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255),
    resource_type VARCHAR(50),
    resource_id VARCHAR(36),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    previous_hash VARCHAR(64),  -- For chain integrity
    signature TEXT  -- Signed entry
);

CREATE TABLE revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id UUID REFERENCES certificates(id),
    serial_number VARCHAR(64) NOT NULL,
    revocation_date TIMESTAMP NOT NULL,
    reason VARCHAR(50),
    invalidity_date TIMESTAMP,
    ca_id UUID REFERENCES certificate_authorities(id),
    crl_number BIGINT
);

-- Indexes
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_not_after ON certificates(not_after);
CREATE INDEX idx_certificates_common_name ON certificates(common_name);
CREATE INDEX idx_certificates_serial ON certificates(serial_number);
CREATE INDEX idx_certificates_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
```

---

## 9. Event System

```python
# plxvault/events/bus.py

import asyncio
import json
from typing import Callable, Dict, List
import redis.asyncio as redis
import structlog

logger = structlog.get_logger()

class EventBus:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: redis.Redis = None
        self.handlers: Dict[str, List[Callable]] = {}
        
    async def connect(self):
        self.redis = await redis.from_url(self.redis_url)
        logger.info("Connected to Redis event bus")
        
    async def disconnect(self):
        if self.redis:
            await self.redis.close()
            
    async def publish(self, event_type: str, data: dict):
        """Publish an event."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        await self.redis.publish(f"plxvault:{event_type}", json.dumps(event, default=str))
        
        # Also store for replay
        await self.redis.lpush(
            f"plxvault:events:{event_type}",
            json.dumps(event, default=str)
        )
        await self.redis.ltrim(f"plxvault:events:{event_type}", 0, 999)
        
        logger.info("Event published", event_type=event_type)
        
    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe to an event type."""
        if event_type not in self.handlers:
            self.handlers[event_type] = []
        self.handlers[event_type].append(handler)
        
    async def start_listener(self):
        """Start listening for events."""
        pubsub = self.redis.pubsub()
        await pubsub.psubscribe("plxvault:*")
        
        async for message in pubsub.listen():
            if message["type"] == "pmessage":
                event_type = message["channel"].decode().replace("plxvault:", "")
                event_data = json.loads(message["data"])
                
                handlers = self.handlers.get(event_type, [])
                for handler in handlers:
                    try:
                        await handler(event_data)
                    except Exception as e:
                        logger.error("Event handler error", error=str(e))

# Event types
EVENTS = {
    "certificate.issued": "Emitted when a certificate is issued",
    "certificate.revoked": "Emitted when a certificate is revoked",
    "certificate.expiring": "Emitted when a certificate is about to expire",
    "certificate.expired": "Emitted when a certificate has expired",
    "certificate.renewed": "Emitted when a certificate is renewed",
    "ca.created": "Emitted when a CA is created",
    "ca.revoked": "Emitted when a CA is revoked",
    "crl.generated": "Emitted when a CRL is regenerated",
    "anomaly.detected": "Emitted when anomalous activity is detected",
}
```

### 9.1 Webhooks

```python
# plxvault/events/webhooks.py

import httpx
from typing import List
import structlog

from plxvault.db.repositories.webhook import WebhookRepository

logger = structlog.get_logger()

class WebhookDispatcher:
    def __init__(self, repo: WebhookRepository):
        self.repo = repo
        
    async def dispatch(self, event_type: str, data: dict):
        """Send webhook notifications for an event."""
        
        webhooks = await self.repo.get_by_event(event_type)
        
        async with httpx.AsyncClient() as client:
            for webhook in webhooks:
                try:
                    response = await client.post(
                        webhook.url,
                        json={
                            "event": event_type,
                            "data": data,
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                        headers={
                            "X-PlxVault-Signature": self.sign(webhook.secret, data),
                            "Content-Type": "application/json",
                        },
                        timeout=10.0,
                    )
                    
                    logger.info(
                        "Webhook sent",
                        url=webhook.url,
                        event=event_type,
                        status=response.status_code,
                    )
                    
                except Exception as e:
                    logger.error(
                        "Webhook failed",
                        url=webhook.url,
                        event=event_type,
                        error=str(e),
                    )
                    
    def sign(self, secret: str, data: dict) -> str:
        """Sign webhook payload."""
        import hmac
        import hashlib
        payload = json.dumps(data, sort_keys=True, default=str)
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
```

---

## 10. Security Model

### 10.1 Authentication

```python
# plxvault/api/middleware/auth.py

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, APIKeyHeader
import jwt

# Multiple auth methods supported
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    request: Request,
    api_key: str = Depends(api_key_header),
    bearer: str = Depends(bearer_scheme),
):
    """Authenticate request via API key, JWT, or mTLS."""
    
    # Method 1: API Key
    if api_key:
        user = await validate_api_key(api_key)
        if user:
            return user
            
    # Method 2: JWT Bearer token
    if bearer:
        user = await validate_jwt(bearer.credentials)
        if user:
            return user
            
    # Method 3: mTLS client certificate
    client_cert = request.headers.get("X-Client-Cert")
    if client_cert:
        user = await validate_client_cert(client_cert)
        if user:
            return user
            
    raise HTTPException(status_code=401, detail="Not authenticated")
```

### 10.2 Authorization (RBAC)

```python
# plxvault/api/middleware/authz.py

from enum import Enum
from typing import List

class Permission(str, Enum):
    # Certificate operations
    CERT_READ = "cert:read"
    CERT_ISSUE = "cert:issue"
    CERT_REVOKE = "cert:revoke"
    
    # CA operations
    CA_READ = "ca:read"
    CA_CREATE = "ca:create"
    CA_MANAGE = "ca:manage"
    
    # Admin
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"

class Role:
    VIEWER = [Permission.CERT_READ, Permission.CA_READ]
    OPERATOR = [Permission.CERT_READ, Permission.CERT_ISSUE, Permission.CA_READ]
    CA_ADMIN = [Permission.CERT_READ, Permission.CERT_ISSUE, Permission.CERT_REVOKE,
                Permission.CA_READ, Permission.CA_CREATE]
    SUPER_ADMIN = list(Permission)

def require_permission(*permissions: Permission):
    """Decorator to require specific permissions."""
    async def checker(user = Depends(get_current_user)):
        for perm in permissions:
            if perm not in user.permissions:
                raise HTTPException(status_code=403, detail=f"Missing permission: {perm}")
        return user
    return checker
```

### 10.3 Key Protection

```python
# plxvault/security/keys.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class KeyProtection:
    """Encrypt private keys at rest."""
    
    def __init__(self, master_key: bytes):
        self.master_key = master_key
        
    def encrypt(self, private_key_pem: bytes) -> bytes:
        """Encrypt a private key."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
        return nonce + ciphertext
        
    def decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt a private key."""
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
```

---

## 11. API Specification

Full OpenAPI spec available at `/openapi.json`

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/certificates | Issue certificate |
| GET | /api/v1/certificates | List certificates |
| GET | /api/v1/certificates/{id} | Get certificate |
| POST | /api/v1/certificates/{id}/revoke | Revoke certificate |
| POST | /api/v1/certificates/{id}/renew | Renew certificate |
| GET | /api/v1/certificates/expiring | Get expiring certs |
| POST | /api/v1/certificates/bulk/issue | Bulk issue |
| GET | /api/v1/cas | List CAs |
| POST | /api/v1/cas | Create CA |
| GET | /api/v1/crl/{ca_name} | Download CRL |
| POST | /api/v1/ocsp | OCSP responder |
| GET | /health | Health check |
| GET | /metrics | Prometheus metrics |

---

## 12. Deployment

### 12.1 Docker Compose (Development)

```yaml
# docker-compose.yml

services:
  plxvault:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://plxvault:plxvault@postgres:5432/plxvault
      - REDIS_URL=redis://redis:6379
      - MASTER_KEY_FILE=/secrets/master.key
    volumes:
      - ./secrets:/secrets:ro
    depends_on:
      - postgres
      - redis
      
  postgres:
    image: postgres:16
    environment:
      - POSTGRES_USER=plxvault
      - POSTGRES_PASSWORD=plxvault
      - POSTGRES_DB=plxvault
    volumes:
      - pgdata:/var/lib/postgresql/data
      
  redis:
    image: redis:7-alpine
    
volumes:
  pgdata:
```

### 12.2 Dockerfile

```dockerfile
# Dockerfile

# Stage 1: Build Rust
FROM rust:1.75 as rust-builder
WORKDIR /build
COPY crates/ crates/
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release -p plxvault-python

# Stage 2: Python
FROM python:3.12-slim
WORKDIR /app

# Install Rust library
COPY --from=rust-builder /build/target/release/libplxvault_python.so /usr/local/lib/

# Install Python dependencies
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --no-dev

# Copy application
COPY plxvault/ plxvault/

# Run
ENV PYTHONPATH=/usr/local/lib
CMD ["uvicorn", "plxvault.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 12.3 Kubernetes (Production)

```yaml
# deploy/kubernetes/deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: plxvault
spec:
  replicas: 3
  selector:
    matchLabels:
      app: plxvault
  template:
    metadata:
      labels:
        app: plxvault
    spec:
      containers:
        - name: plxvault
          image: plxvault:latest
          ports:
            - containerPort: 8000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: plxvault-secrets
                  key: database-url
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
```

---

## 13. Roadmap

### Phase 1: Core (Weeks 1-4)
- [ ] Rust crypto core with PyO3 bindings
- [ ] Basic certificate operations (issue, revoke, renew)
- [ ] REST API with FastAPI
- [ ] PostgreSQL storage
- [ ] MCP server integration

### Phase 2: Production Ready (Weeks 5-8)
- [ ] ACME protocol support
- [ ] CRL and OCSP
- [ ] Event system with webhooks
- [ ] Authentication (API key, JWT, mTLS)
- [ ] RBAC authorization
- [ ] Audit logging

### Phase 3: Enterprise Features (Weeks 9-12)
- [ ] Post-quantum cryptography (ML-DSA, ML-KEM)
- [ ] HSM integration (PKCS#11)
- [ ] Multi-tenancy
- [ ] High availability setup
- [ ] Kubernetes operator

### Phase 4: Advanced (Weeks 13-16)
- [ ] SPIFFE/SPIRE integration
- [ ] Short-lived certificate automation
- [ ] Anomaly detection
- [ ] GitOps reconciler
- [ ] Web UI dashboard

---

## Appendix A: Configuration

```yaml
# config.yaml

server:
  host: 0.0.0.0
  port: 8000
  workers: 4

database:
  url: postgresql://localhost/plxvault
  pool_size: 20

redis:
  url: redis://localhost:6379

security:
  master_key_source: env  # env, file, vault, hsm
  master_key_env: PLXVAULT_MASTER_KEY
  jwt_secret: ${JWT_SECRET}
  jwt_algorithm: ES256
  
default_ca: PlxVault-Root-CA

certificate_defaults:
  validity_days: 365
  key_algorithm: ecdsa-p256
  
pqc:
  enabled: true
  default_hybrid: true
  algorithms:
    - ml-dsa-65
    - ml-kem-768

acme:
  enabled: true
  challenges:
    - http-01
    - dns-01
    
logging:
  level: INFO
  format: json
```

---

## Appendix B: Dependencies

### Rust (Cargo.toml)
```toml
[dependencies]
rcgen = "0.12"
ring = "0.17"
pqcrypto-dilithium = "0.5"
pqcrypto-kyber = "0.8"
x509-parser = "0.15"
pem = "3.0"
hex = "0.4"
thiserror = "1.0"
pyo3 = { version = "0.20", features = ["extension-module"] }
```

### Python (pyproject.toml)
```toml
[tool.poetry.dependencies]
python = "^3.12"
fastapi = "^0.109"
uvicorn = "^0.27"
sqlalchemy = "^2.0"
asyncpg = "^0.29"
redis = "^5.0"
httpx = "^0.26"
pydantic = "^2.6"
structlog = "^24.1"
cryptography = "^42.0"
```

---

**Document Version:** 1.0.0-draft
**Last Updated:** 2026-05-25
**Author:** PlxVault Team
