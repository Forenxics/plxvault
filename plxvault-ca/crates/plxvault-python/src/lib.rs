//! Python bindings for PlxVault Core
//!
//! Exposes the Rust crypto core to Python via PyO3.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use ::plxvault_core::{
    keys::{KeyAlgorithm, KeyPair},
    certs::{CertificateAuthority, CertificateRequest, IssuedCertificate, KeyUsage, ExtendedKeyUsage},
};

/// Key algorithm enum exposed to Python
#[pyclass(name = "KeyAlgorithm")]
#[derive(Clone)]
pub struct PyKeyAlgorithm(KeyAlgorithm);

#[pymethods]
impl PyKeyAlgorithm {
    #[staticmethod]
    fn rsa_2048() -> Self {
        Self(KeyAlgorithm::Rsa2048)
    }

    #[staticmethod]
    fn rsa_4096() -> Self {
        Self(KeyAlgorithm::Rsa4096)
    }

    #[staticmethod]
    fn ecdsa_p256() -> Self {
        Self(KeyAlgorithm::EcdsaP256)
    }

    #[staticmethod]
    fn ecdsa_p384() -> Self {
        Self(KeyAlgorithm::EcdsaP384)
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

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __repr__(&self) -> String {
        format!("KeyAlgorithm.{}", self.0.to_string().replace("-", "_"))
    }

    fn is_post_quantum(&self) -> bool {
        self.0.is_post_quantum()
    }

    fn is_hybrid(&self) -> bool {
        self.0.is_hybrid()
    }
}

/// Key pair exposed to Python
#[pyclass(name = "KeyPair")]
pub struct PyKeyPair {
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
    fn algorithm(&self) -> PyKeyAlgorithm {
        PyKeyAlgorithm(self.inner.algorithm)
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.clone()
    }

    #[getter]
    fn public_key_pem(&self) -> String {
        self.inner.public_key_pem()
    }

    #[getter]
    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    #[getter]
    fn created_at(&self) -> u64 {
        self.inner.created_at
    }
}

/// Issued certificate exposed to Python
#[pyclass(name = "IssuedCertificate")]
#[derive(Clone)]
pub struct PyIssuedCertificate {
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
    fn chain_pem(&self) -> Option<&str> {
        self.inner.chain_pem.as_deref()
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

    fn to_dict(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

/// Certificate Authority exposed to Python
#[pyclass(name = "CertificateAuthority")]
pub struct PyCertificateAuthority {
    inner: CertificateAuthority,
}

#[pymethods]
impl PyCertificateAuthority {
    /// Create a new root CA
    #[staticmethod]
    #[pyo3(signature = (common_name, algorithm, validity_years=10, organization=None))]
    fn create_root(
        common_name: &str,
        algorithm: PyKeyAlgorithm,
        validity_years: u32,
        organization: Option<&str>,
    ) -> PyResult<(Self, PyIssuedCertificate)> {
        CertificateAuthority::create_root(common_name, organization, algorithm.0, validity_years)
            .map(|(ca, cert)| {
                (
                    Self { inner: ca },
                    PyIssuedCertificate { inner: cert },
                )
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Create an intermediate CA signed by this CA
    #[pyo3(signature = (common_name, algorithm, validity_years=5, path_length=0, organization=None))]
    fn create_intermediate(
        &self,
        common_name: &str,
        algorithm: PyKeyAlgorithm,
        validity_years: u32,
        path_length: u8,
        organization: Option<&str>,
    ) -> PyResult<(Self, PyIssuedCertificate)> {
        self.inner
            .create_intermediate(common_name, organization, algorithm.0, validity_years, path_length)
            .map(|(ca, cert)| {
                (
                    Self { inner: ca },
                    PyIssuedCertificate { inner: cert },
                )
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Issue an end-entity certificate
    #[pyo3(signature = (common_name, validity_days=365, san_dns=None, san_ips=None, organization=None, country=None))]
    fn issue_certificate(
        &self,
        common_name: &str,
        validity_days: u32,
        san_dns: Option<Vec<String>>,
        san_ips: Option<Vec<String>>,
        organization: Option<String>,
        country: Option<String>,
    ) -> PyResult<PyIssuedCertificate> {
        let request = CertificateRequest {
            common_name: common_name.to_string(),
            organization,
            country,
            san_dns: san_dns.unwrap_or_default(),
            san_ips: san_ips.unwrap_or_default(),
            validity_days,
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
            ..Default::default()
        };

        self.inner
            .issue_certificate(request)
            .map(|cert| PyIssuedCertificate { inner: cert })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Get CA certificate PEM
    #[getter]
    fn certificate_pem(&self) -> &str {
        self.inner.certificate_pem()
    }

    /// Get CA common name
    #[getter]
    fn common_name(&self) -> String {
        self.inner.common_name()
    }
}

/// Python module definition
#[pymodule]
fn plxvault_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyKeyAlgorithm>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyIssuedCertificate>()?;
    m.add_class::<PyCertificateAuthority>()?;

    // Add version info
    m.add("__version__", "0.1.0")?;
    m.add("__doc__", "PlxVault CA - AI-native PKI crypto core")?;

    Ok(())
}
