# PlxVault CA

AI-native, post-quantum ready Certificate Authority.

## Features

- **Rust Crypto Core**: Memory-safe, high-performance cryptographic operations
- **Post-Quantum Ready**: ML-DSA (Dilithium), hybrid ECDSA+ML-DSA schemes
- **AI-Native**: MCP server for natural language certificate management
- **Modern API**: FastAPI REST interface
- **Short-Lived Certs**: SPIFFE/SPIRE compatible

## Quick Start

### Prerequisites

- Rust 1.75+
- Python 3.11+
- maturin (`pip install maturin`)

### Build

```bash
# Build Rust core and Python bindings
maturin develop

# Or build release wheel
maturin build --release
```

### Run API Server

```bash
uvicorn plxvault.api:app --reload
```

### Run MCP Server

```bash
plxvault-mcp
```

Or add to Claude Code (`~/.claude/mcp_settings.json`):

```json
{
  "mcpServers": {
    "plxvault": {
      "command": "plxvault-mcp"
    }
  }
}
```

## Usage

### Python

```python
from plxvault import CertificateAuthority, KeyAlgorithm

# Create a root CA
ca, root_cert = CertificateAuthority.create_root(
    "My Root CA",
    KeyAlgorithm.ecdsa_p256(),
    validity_years=10
)

# Issue a certificate
cert = ca.issue_certificate(
    "server.example.com",
    validity_days=365,
    san_dns=["www.example.com", "api.example.com"]
)

print(cert.certificate_pem)
print(cert.private_key_pem)
```

### REST API

```bash
# Create CA
curl -X POST http://localhost:8000/api/v1/cas \
  -H "Content-Type: application/json" \
  -d '{"name": "my-ca", "common_name": "My CA"}'

# Issue certificate
curl -X POST http://localhost:8000/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{"common_name": "server.example.com"}'

# List expiring certificates
curl http://localhost:8000/api/v1/certificates/expiring?days=30
```

### MCP (AI Agent)

```
User: "Issue a certificate for api.example.com"
AI: Done. Certificate issued with serial ABC123, expires in 365 days.

User: "What's expiring in the next 30 days?"
AI: Found 3 certificates expiring soon: web1, web2, db1

User: "Renew them all"
AI: Renewed 3 certificates.
```

## Post-Quantum Cryptography

PlxVault supports NIST post-quantum standards:

```python
# Pure post-quantum (ML-DSA-65 / Dilithium3)
ca, cert = CertificateAuthority.create_root(
    "PQC Root CA",
    KeyAlgorithm.ml_dsa_65()
)

# Hybrid (ECDSA P-256 + ML-DSA-65) - recommended for transition
ca, cert = CertificateAuthority.create_root(
    "Hybrid Root CA",
    KeyAlgorithm.hybrid_ecdsa_mldsa()
)
```

## Architecture

```
┌─────────────────────────────────────────────┐
│  AI Agents (Claude, etc.)                   │
└─────────────────────────────────────────────┘
                    ↓ MCP
┌─────────────────────────────────────────────┐
│  Python API Layer (FastAPI)                 │
│  - REST API                                 │
│  - MCP Server                               │
│  - Business Logic                           │
└─────────────────────────────────────────────┘
                    ↓ PyO3
┌─────────────────────────────────────────────┐
│  Rust Crypto Core                           │
│  - Key Generation                           │
│  - Certificate Signing                      │
│  - PQC (ML-DSA, Hybrid)                    │
└─────────────────────────────────────────────┘
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black plxvault/
ruff check plxvault/

# Type check
mypy plxvault/
```

## License

MIT
