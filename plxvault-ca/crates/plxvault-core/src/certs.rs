//! Certificate operations: creation, signing, parsing

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair as RcgenKeyPair, KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ::time::{Duration, OffsetDateTime};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::X509Certificate;

use crate::error::{Error, Result};
use crate::keys::KeyAlgorithm;

/// Certificate request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub common_name: String,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub organizational_unit: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub san_dns: Vec<String>,
    #[serde(default)]
    pub san_ips: Vec<String>,
    #[serde(default)]
    pub san_emails: Vec<String>,
    #[serde(default)]
    pub san_uris: Vec<String>,
    #[serde(default = "default_validity")]
    pub validity_days: u32,
    #[serde(default)]
    pub is_ca: bool,
    #[serde(default)]
    pub path_length: Option<u8>,
    #[serde(default)]
    pub key_usage: Vec<KeyUsage>,
    #[serde(default)]
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
}

fn default_validity() -> u32 {
    365
}

impl Default for CertificateRequest {
    fn default() -> Self {
        Self {
            common_name: String::new(),
            organization: None,
            organizational_unit: None,
            country: None,
            locality: None,
            state: None,
            san_dns: Vec::new(),
            san_ips: Vec::new(),
            san_emails: Vec::new(),
            san_uris: Vec::new(),
            validity_days: 365,
            is_ca: false,
            path_length: None,
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    CertSign,
    CrlSign,
    ContentCommitment,
    DataEncipherment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

/// An issued certificate with all details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    pub serial_number: String,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub fingerprint_sha256: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub key_algorithm: KeyAlgorithm,
}

/// Certificate Authority for issuing certificates
pub struct CertificateAuthority {
    certificate: Certificate,
    key_pair: RcgenKeyPair,
    common_name: String,
    cert_pem: String,
    key_algorithm: KeyAlgorithm,
}

impl CertificateAuthority {
    /// Create a new root CA
    pub fn create_root(
        common_name: &str,
        organization: Option<&str>,
        algorithm: KeyAlgorithm,
        validity_years: u32,
    ) -> Result<(Self, IssuedCertificate)> {
        let mut params = CertificateParams::default();

        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        if let Some(org) = organization {
            dn.push(DnType::OrganizationName, org);
        }
        params.distinguished_name = dn;

        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after =
            OffsetDateTime::now_utc() + Duration::days(validity_years as i64 * 365);

        // CA constraints
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Generate key pair
        let key_pair = Self::generate_rcgen_keypair(algorithm)?;

        // Save values before params is consumed
        let not_before = params.not_before;
        let not_after = params.not_after;
        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        // Self-sign (consumes params)
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        let issued = IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem.clone(),
            private_key_pem: Some(key_pem),
            chain_pem: None,
            not_before: not_before.unix_timestamp() as u64,
            not_after: not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: common_name.to_string(),
            issuer_dn: common_name.to_string(),
            key_algorithm: algorithm,
        };

        Ok((
            Self {
                certificate: cert,
                key_pair,
                common_name: common_name.to_string(),
                cert_pem,
                key_algorithm: algorithm,
            },
            issued,
        ))
    }

    /// Reconstruct a CA from stored certificate and private key PEM
    ///
    /// This allows restoring a CA after server restart without generating new keys.
    pub fn from_stored(
        certificate_pem: &str,
        private_key_pem: &str,
        algorithm: KeyAlgorithm,
    ) -> Result<Self> {
        // Parse the certificate PEM to extract the X.509 certificate
        let (_, pem) = parse_x509_pem(certificate_pem.as_bytes())
            .map_err(|e| Error::Parsing(format!("Failed to parse certificate PEM: {}", e)))?;

        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| Error::Parsing(format!("Failed to parse X.509 certificate: {}", e)))?;

        // Extract common name from subject
        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .ok_or_else(|| Error::Parsing("Certificate has no Common Name".to_string()))?
            .to_string();

        // Load the private key from PEM
        let key_pair = RcgenKeyPair::from_pem(private_key_pem)
            .map_err(|e| Error::Parsing(format!("Failed to parse private key PEM: {}", e)))?;

        // Recreate certificate params with the same DN for signing capability
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &common_name);

        // Also extract organization if present
        if let Some(org) = cert.subject().iter_organization().next() {
            if let Ok(org_str) = org.as_str() {
                dn.push(DnType::OrganizationName, org_str);
            }
        }
        params.distinguished_name = dn;

        // CA constraints
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Use original validity from stored cert
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        params.not_before = OffsetDateTime::from_unix_timestamp(not_before)
            .map_err(|e| Error::Parsing(format!("Invalid not_before timestamp: {}", e)))?;
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after)
            .map_err(|e| Error::Parsing(format!("Invalid not_after timestamp: {}", e)))?;

        // Self-sign with the loaded key to create a signing context
        // Note: This creates a new cert internally, but we keep the original PEM for chains
        let signing_cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Signing(format!("Failed to create signing context: {}", e)))?;

        Ok(Self {
            certificate: signing_cert,
            key_pair,
            common_name,
            cert_pem: certificate_pem.to_string(),
            key_algorithm: algorithm,
        })
    }

    /// Create an intermediate CA signed by this CA
    pub fn create_intermediate(
        &self,
        common_name: &str,
        organization: Option<&str>,
        algorithm: KeyAlgorithm,
        validity_years: u32,
        path_length: u8,
    ) -> Result<(Self, IssuedCertificate)> {
        let mut params = CertificateParams::default();

        // Distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        if let Some(org) = organization {
            dn.push(DnType::OrganizationName, org);
        }
        params.distinguished_name = dn;

        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after =
            OffsetDateTime::now_utc() + Duration::days(validity_years as i64 * 365);

        // CA constraints with path length
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_length));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Generate key pair for intermediate
        let key_pair = Self::generate_rcgen_keypair(algorithm)?;

        // Save values before params is consumed
        let not_before = params.not_before;
        let not_after = params.not_after;
        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        // Sign with parent CA (consumes params)
        let cert = params
            .signed_by(&key_pair, &self.certificate, &self.key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        // Build chain
        let chain_pem = format!("{}\n{}", cert_pem, self.cert_pem);

        let issued = IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem.clone(),
            private_key_pem: Some(key_pem),
            chain_pem: Some(chain_pem),
            not_before: not_before.unix_timestamp() as u64,
            not_after: not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: common_name.to_string(),
            issuer_dn: self.common_name.clone(),
            key_algorithm: algorithm,
        };

        Ok((
            Self {
                certificate: cert,
                key_pair,
                common_name: common_name.to_string(),
                cert_pem,
                key_algorithm: algorithm,
            },
            issued,
        ))
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
        if let Some(locality) = &request.locality {
            dn.push(DnType::LocalityName, locality);
        }
        if let Some(state) = &request.state {
            dn.push(DnType::StateOrProvinceName, state);
        }
        params.distinguished_name = dn;

        // Subject Alternative Names
        let mut sans = Vec::new();

        // Always include CN as SAN for TLS compatibility
        if !request.san_dns.contains(&request.common_name) {
            sans.push(SanType::DnsName(request.common_name.clone().try_into().map_err(|e| Error::Parsing(format!("{:?}", e)))?));
        }

        for dns in &request.san_dns {
            sans.push(SanType::DnsName(dns.clone().try_into().map_err(|e| Error::Parsing(format!("{:?}", e)))?));
        }
        for ip in &request.san_ips {
            if let Ok(ip_addr) = ip.parse() {
                sans.push(SanType::IpAddress(ip_addr));
            }
        }
        for email in &request.san_emails {
            sans.push(SanType::Rfc822Name(email.clone().try_into().map_err(|e| Error::Parsing(format!("{:?}", e)))?));
        }
        for uri in &request.san_uris {
            sans.push(SanType::URI(uri.clone().try_into().map_err(|e| Error::Parsing(format!("{:?}", e)))?));
        }
        params.subject_alt_names = sans;

        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after =
            OffsetDateTime::now_utc() + Duration::days(request.validity_days as i64);

        // CA or end-entity
        if request.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(
                request.path_length.unwrap_or(0),
            ));
        } else {
            params.is_ca = IsCa::NoCa;
        }

        // Key usage
        params.key_usages = request
            .key_usage
            .iter()
            .map(|ku| match ku {
                KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
                KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
                KeyUsage::KeyAgreement => KeyUsagePurpose::KeyAgreement,
                KeyUsage::CertSign => KeyUsagePurpose::KeyCertSign,
                KeyUsage::CrlSign => KeyUsagePurpose::CrlSign,
                KeyUsage::ContentCommitment => KeyUsagePurpose::ContentCommitment,
                KeyUsage::DataEncipherment => KeyUsagePurpose::DataEncipherment,
            })
            .collect();

        // Extended key usage
        params.extended_key_usages = request
            .extended_key_usage
            .iter()
            .map(|eku| match eku {
                ExtendedKeyUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsage::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
                ExtendedKeyUsage::EmailProtection => ExtendedKeyUsagePurpose::EmailProtection,
                ExtendedKeyUsage::TimeStamping => ExtendedKeyUsagePurpose::TimeStamping,
                ExtendedKeyUsage::OcspSigning => ExtendedKeyUsagePurpose::OcspSigning,
            })
            .collect();

        // Generate key pair for the certificate
        let key_pair = Self::generate_rcgen_keypair(self.key_algorithm)?;

        // Save values before params is consumed
        let not_before = params.not_before;
        let not_after = params.not_after;
        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        // Sign with CA (consumes params)
        let cert = params
            .signed_by(&key_pair, &self.certificate, &self.key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        // Build chain
        let chain_pem = format!("{}\n{}", cert_pem, self.cert_pem);

        Ok(IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            chain_pem: Some(chain_pem),
            not_before: not_before.unix_timestamp() as u64,
            not_after: not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: request.common_name,
            issuer_dn: self.common_name.clone(),
            key_algorithm: self.key_algorithm,
        })
    }

    /// Get CA certificate PEM
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get CA common name
    pub fn common_name(&self) -> String {
        self.common_name.clone()
    }

    fn generate_rcgen_keypair(algorithm: KeyAlgorithm) -> Result<RcgenKeyPair> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => RcgenKeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| Error::KeyGeneration(e.to_string())),
            KeyAlgorithm::EcdsaP384 => RcgenKeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
                .map_err(|e| Error::KeyGeneration(e.to_string())),
            KeyAlgorithm::Ed25519 => RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519)
                .map_err(|e| Error::KeyGeneration(e.to_string())),
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Algorithm {:?} not supported for certificate generation with rcgen",
                algorithm
            ))),
        }
    }

    fn calculate_fingerprint_from_pem(pem_str: &str) -> Result<String> {
        let (_, pem) = parse_x509_pem(pem_str.as_bytes())
            .map_err(|e| Error::Parsing(format!("Failed to parse PEM: {}", e)))?;
        let hash = Sha256::digest(&pem.contents);
        Ok(hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_root_ca() {
        let (ca, issued) = CertificateAuthority::create_root(
            "Test Root CA",
            Some("Test Org"),
            KeyAlgorithm::EcdsaP256,
            10,
        )
        .unwrap();

        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.private_key_pem.unwrap().contains("BEGIN PRIVATE KEY"));
        assert_eq!(issued.subject_dn, "Test Root CA");
        assert_eq!(issued.issuer_dn, "Test Root CA");
        assert_eq!(ca.common_name(), "Test Root CA");
    }

    #[test]
    fn test_issue_certificate() {
        let (ca, _) = CertificateAuthority::create_root(
            "Test Root CA",
            None,
            KeyAlgorithm::EcdsaP256,
            10,
        )
        .unwrap();

        let request = CertificateRequest {
            common_name: "test.example.com".to_string(),
            san_dns: vec!["www.example.com".to_string()],
            validity_days: 365,
            ..Default::default()
        };

        let cert = ca.issue_certificate(request).unwrap();

        assert!(cert.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.chain_pem.is_some());
        assert_eq!(cert.subject_dn, "test.example.com");
        assert_eq!(cert.issuer_dn, "Test Root CA");
    }

    #[test]
    fn test_create_intermediate_ca() {
        let (root_ca, _) = CertificateAuthority::create_root(
            "Test Root CA",
            None,
            KeyAlgorithm::EcdsaP256,
            10,
        )
        .unwrap();

        let (intermediate_ca, intermediate_cert) = root_ca
            .create_intermediate(
                "Test Intermediate CA",
                None,
                KeyAlgorithm::EcdsaP256,
                5,
                0,
            )
            .unwrap();

        assert_eq!(intermediate_cert.subject_dn, "Test Intermediate CA");
        assert_eq!(intermediate_cert.issuer_dn, "Test Root CA");

        // Issue cert from intermediate
        let request = CertificateRequest {
            common_name: "leaf.example.com".to_string(),
            ..Default::default()
        };

        let leaf = intermediate_ca.issue_certificate(request).unwrap();
        assert_eq!(leaf.issuer_dn, "Test Intermediate CA");
    }

    #[test]
    fn test_from_stored() {
        // Create a CA
        let (original_ca, issued) = CertificateAuthority::create_root(
            "Stored CA Test",
            Some("Test Org"),
            KeyAlgorithm::EcdsaP256,
            10,
        )
        .unwrap();

        let cert_pem = issued.certificate_pem.clone();
        let key_pem = issued.private_key_pem.unwrap();

        // Reconstruct CA from stored data
        let restored_ca = CertificateAuthority::from_stored(
            &cert_pem,
            &key_pem,
            KeyAlgorithm::EcdsaP256,
        )
        .unwrap();

        assert_eq!(restored_ca.common_name(), "Stored CA Test");

        // Issue a certificate with restored CA
        let request = CertificateRequest {
            common_name: "restored.example.com".to_string(),
            ..Default::default()
        };

        let cert = restored_ca.issue_certificate(request).unwrap();
        assert!(cert.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(cert.subject_dn, "restored.example.com");
        assert_eq!(cert.issuer_dn, "Stored CA Test");
    }
}
