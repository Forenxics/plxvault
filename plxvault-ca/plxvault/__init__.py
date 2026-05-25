"""
PlxVault CA - AI-native, Post-Quantum Ready Certificate Authority

A modern PKI solution designed for the AI era with:
- Rust crypto core for performance and safety
- Post-quantum cryptography support (ML-DSA, hybrid schemes)
- MCP integration for AI agent access
- REST API for automation
- Short-lived certificate support

Example:
    >>> from plxvault import CertificateAuthority, KeyAlgorithm
    >>> ca, root_cert = CertificateAuthority.create_root(
    ...     "My Root CA",
    ...     KeyAlgorithm.ecdsa_p256()
    ... )
    >>> cert = ca.issue_certificate("server.example.com")
    >>> print(cert.certificate_pem)
"""

__version__ = "0.1.0"
__author__ = "PlxVault Team"

# Re-export from Rust core (when built)
try:
    from plxvault.plxvault_core import (
        KeyAlgorithm,
        KeyPair,
        CertificateAuthority,
        IssuedCertificate,
    )
except ImportError:
    # Rust extension not built yet
    KeyAlgorithm = None
    KeyPair = None
    CertificateAuthority = None
    IssuedCertificate = None

__all__ = [
    "KeyAlgorithm",
    "KeyPair",
    "CertificateAuthority",
    "IssuedCertificate",
    "__version__",
]
