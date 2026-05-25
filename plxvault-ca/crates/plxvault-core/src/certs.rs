//! Certificate operations: creation, signing, parsing

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair as RcgenKeyPair, KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

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
    params: CertificateParams,
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

        // Self-sign
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        let issued = IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem.clone(),
            private_key_pem: Some(key_pem),
            chain_pem: None,
            not_before: params.not_before.unix_timestamp() as u64,
            not_after: params.not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: common_name.to_string(),
            issuer_dn: common_name.to_string(),
            key_algorithm: algorithm,
        };

        Ok((
            Self {
                certificate: cert,
                key_pair,
                params,
                cert_pem,
                key_algorithm: algorithm,
            },
            issued,
        ))
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

        // Sign with parent CA
        let cert = params
            .signed_by(&key_pair, &self.certificate, &self.key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        // Build chain
        let chain_pem = format!("{}\n{}", cert_pem, self.cert_pem);

        let parent_cn = self
            .params
            .distinguished_name
            .get(&DnType::CommonName)
            .map(|s| s.to_string())
            .unwrap_or_default();

        let issued = IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem.clone(),
            private_key_pem: Some(key_pem),
            chain_pem: Some(chain_pem),
            not_before: params.not_before.unix_timestamp() as u64,
            not_after: params.not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: common_name.to_string(),
            issuer_dn: parent_cn,
            key_algorithm: algorithm,
        };

        Ok((
            Self {
                certificate: cert,
                key_pair,
                params,
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

        // Sign with CA
        let cert = params
            .signed_by(&key_pair, &self.certificate, &self.key_pair)
            .map_err(|e| Error::Signing(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let serial = params
            .serial_number
            .as_ref()
            .map(|s| hex::encode(s.as_ref()))
            .unwrap_or_else(|| "unknown".to_string());

        let fingerprint = Self::calculate_fingerprint_from_pem(&cert_pem)?;

        // Build chain
        let chain_pem = format!("{}\n{}", cert_pem, self.cert_pem);

        let issuer_cn = self
            .params
            .distinguished_name
            .get(&DnType::CommonName)
            .map(|s| s.to_string())
            .unwrap_or_default();

        Ok(IssuedCertificate {
            serial_number: serial,
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            chain_pem: Some(chain_pem),
            not_before: params.not_before.unix_timestamp() as u64,
            not_after: params.not_after.unix_timestamp() as u64,
            fingerprint_sha256: fingerprint,
            subject_dn: request.common_name,
            issuer_dn: issuer_cn,
            key_algorithm: self.key_algorithm,
        })
    }

    /// Get CA certificate PEM
    pub fn certificate_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get CA common name
    pub fn common_name(&self) -> String {
        self.params
            .distinguished_name
            .get(&DnType::CommonName)
            .map(|s| s.to_string())
            .unwrap_or_default()
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
        let pem_data = pem::parse(pem_str).map_err(|e| Error::Parsing(e.to_string()))?;
        let hash = Sha256::digest(pem_data.contents());
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
}
