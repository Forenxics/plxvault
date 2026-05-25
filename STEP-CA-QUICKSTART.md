# step-ca Quick Start

Modern, API-first certificate authority running alongside EJBCA for comparison.

## Start Both CAs

```bash
docker compose up -d
```

## Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| EJBCA Admin | https://localhost:8443/ejbca/adminweb/ | Enterprise PKI management |
| EJBCA RA | https://localhost:8443/ejbca/ra/ | Registration Authority |
| step-ca | https://localhost:9000 | Modern CA API |

## step-ca: Issue a Certificate (One Command)

```bash
# Enter the CLI container
docker exec -it step-cli sh

# Bootstrap trust (first time only)
step ca bootstrap --ca-url https://step-ca:9000 --fingerprint $(step certificate fingerprint /home/step/certs/root_ca.crt)

# Issue a certificate
step ca certificate myserver.local server.crt server.key

# That's it!
```

## step-ca: REST API Examples

```bash
# Get CA health
curl -k https://localhost:9000/health

# Get root certificate
curl -k https://localhost:9000/root/$(step certificate fingerprint /home/step/certs/root_ca.crt)

# List provisioners
curl -k https://localhost:9000/provisioners
```

## step-ca: ACME (Auto-Renewal)

step-ca has built-in ACME support, same protocol as Let's Encrypt:

```bash
# On your server, use certbot or any ACME client
certbot certonly \
  --server https://step-ca:9000/acme/acme/directory \
  --standalone \
  -d myserver.local
```

## Compare: Issue Certificate for 10 Servers

### step-ca (10 seconds)
```bash
for i in {1..10}; do
  step ca certificate server${i}.local server${i}.crt server${i}.key --not-after 8760h
done
```

### EJBCA (10+ minutes)
1. Create End Entity Profile (if not exists)
2. Create Certificate Profile (if not exists)
3. For each server:
   - Add End Entity via GUI or API
   - Set password
   - Generate CSR on server
   - Submit CSR via GUI or API
   - Download certificate

## AI Integration Ready

step-ca's clean API makes it trivial to wrap with an MCP server:

```python
# Pseudo-code for MCP tool
@tool
def issue_certificate(hostname: str, validity_days: int = 365):
    """Issue a TLS certificate for the given hostname."""
    result = subprocess.run([
        "step", "ca", "certificate",
        hostname,
        f"{hostname}.crt",
        f"{hostname}.key",
        "--not-after", f"{validity_days * 24}h"
    ])
    return {"cert": f"{hostname}.crt", "key": f"{hostname}.key"}
```

## Default Credentials

step-ca auto-generates a password on first run. Find it:

```bash
docker exec step-ca cat /home/step/secrets/password
```

## Architecture Comparison

```
EJBCA Stack:                    step-ca Stack:
┌─────────────────────┐         ┌─────────────────────┐
│ WildFly/JBoss       │         │ Single Go binary    │
│ Java EE             │         │ ~20MB container     │
│ JSF/PrimeFaces      │         │ REST API only       │
│ PostgreSQL/MariaDB  │         │ BadgerDB (embedded) │
│ ~500MB container    │         │                     │
└─────────────────────┘         └─────────────────────┘
```

## When to Use Which

| Use Case | Recommendation |
|----------|----------------|
| Quick internal certs | step-ca |
| Auto-renewal (ACME) | step-ca |
| AI/automation first | step-ca |
| Compliance (eIDAS, WebTrust) | EJBCA |
| HSM integration | EJBCA |
| Complex CA hierarchies | EJBCA |
| Audit trails | EJBCA |
