#!/bin/bash
# Compare EJBCA vs step-ca for certificate issuance
# Usage: ./scripts/compare-ca.sh

set -e

echo "=========================================="
echo "  PKI Comparison: EJBCA vs step-ca"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[step-ca] Issuing a certificate...${NC}"
echo ""
echo "Command:"
echo "  docker exec step-cli step ca certificate myserver.local /certs/server.crt /certs/server.key --ca-url https://step-ca:9000 --root /home/step/certs/root_ca.crt"
echo ""

# Get the provisioner password
FINGERPRINT=$(docker exec step-ca step certificate fingerprint /home/step/certs/root_ca.crt 2>/dev/null || echo "")

if [ -z "$FINGERPRINT" ]; then
    echo "step-ca not running. Start with: docker compose up -d"
    exit 1
fi

echo "Root CA Fingerprint: $FINGERPRINT"
echo ""

# Issue cert with step-ca (interactive, will prompt for password)
echo "Issuing certificate for myserver.local..."
docker exec -it step-cli step ca certificate myserver.local /certs/server.crt /certs/server.key \
    --ca-url https://step-ca:9000 \
    --root /home/step/certs/root_ca.crt \
    --not-after 8760h

echo ""
echo -e "${GREEN}[step-ca] Certificate issued!${NC}"
echo ""
echo "Files created:"
docker exec step-cli ls -la /certs/

echo ""
echo "Certificate details:"
docker exec step-cli step certificate inspect /certs/server.crt --short

echo ""
echo "=========================================="
echo -e "${BLUE}[EJBCA] To issue the same certificate:${NC}"
echo "=========================================="
echo ""
echo "1. Admin GUI → RA Functions → Add End Entity"
echo "2. Fill form: Username, CN, Certificate Profile, End Entity Profile, Token"
echo "3. Set status to NEW"
echo "4. Public Web → Create Certificate from CSR"
echo "5. Or use REST API (Enterprise only for full features)"
echo ""
echo "Lines of code for same result:"
echo "  step-ca:  1 command"
echo "  EJBCA:    Multiple GUI steps or 50+ lines of API code"
