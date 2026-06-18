"""Certificate management routes."""

from typing import List, Optional
from datetime import datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field

from plxvault.db import CARepository, CertificateRepository
from plxvault.api.routes.cas import get_ca_object

router = APIRouter()


class CertificateType(str, Enum):
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code-signing"
    EMAIL = "email"


class CertificateStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KeyAlgorithm(str, Enum):
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"
    HYBRID_ECDSA_MLDSA = "hybrid-ecdsa-mldsa"


class RevocationReason(str, Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key-compromise"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation-of-operation"


class IssueCertificateRequest(BaseModel):
    """Request to issue a new certificate."""

    common_name: str = Field(..., min_length=1, max_length=255)
    certificate_type: CertificateType = CertificateType.SERVER
    san_dns: List[str] = Field(default_factory=list)
    san_ips: List[str] = Field(default_factory=list)
    organization: Optional[str] = None
    country: Optional[str] = Field(None, min_length=2, max_length=2)
    validity_days: int = Field(365, ge=1, le=3650)
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ECDSA_P256
    ca_name: Optional[str] = None
    csr: Optional[str] = Field(None, description="PEM-encoded CSR")


class CertificateResponse(BaseModel):
    """Certificate response."""

    id: str
    serial_number: str
    common_name: str
    status: str
    certificate_pem: str
    private_key_pem: Optional[str] = None
    chain_pem: Optional[str] = None
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    subject_dn: str
    issuer_dn: str
    key_algorithm: str
    certificate_type: str
    revocation_date: Optional[datetime] = None
    revocation_reason: Optional[str] = None


class CertificateListResponse(BaseModel):
    """List of certificates response."""

    certificates: List[CertificateResponse]
    total: int


class RevokeCertificateRequest(BaseModel):
    """Request to revoke a certificate."""

    reason: RevocationReason = RevocationReason.UNSPECIFIED


class BulkIssueRequest(BaseModel):
    """Request to issue multiple certificates."""

    hosts: List[str]
    validity_days: int = Field(365, ge=1, le=3650)
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ECDSA_P256
    ca_name: Optional[str] = None


class BulkIssueResponse(BaseModel):
    """Bulk issue response."""

    issued: List[CertificateResponse]
    failed: List[dict]


def _cert_dict_to_response(cert: dict) -> CertificateResponse:
    """Convert certificate dict to response model."""
    return CertificateResponse(
        id=cert["id"],
        serial_number=cert["serial_number"],
        common_name=cert["common_name"],
        status=cert["status"],
        certificate_pem=cert["certificate_pem"],
        private_key_pem=cert.get("private_key_pem"),
        chain_pem=cert.get("chain_pem"),
        fingerprint_sha256=cert["fingerprint_sha256"],
        not_before=cert["not_before"],
        not_after=cert["not_after"],
        subject_dn=cert["subject_dn"],
        issuer_dn=cert["issuer_dn"],
        key_algorithm=cert["key_algorithm"],
        certificate_type=cert["certificate_type"],
        revocation_date=cert.get("revocation_date"),
        revocation_reason=cert.get("revocation_reason"),
    )


@router.post("", response_model=CertificateResponse)
async def issue_certificate(
    request: IssueCertificateRequest,
    background_tasks: BackgroundTasks,
):
    """Issue a new certificate."""
    # Get CA
    cas = await CARepository.list_all(is_active=True, limit=1)
    if not cas:
        raise HTTPException(
            status_code=404,
            detail="No active CA found. Create a CA first.",
        )

    ca_name = request.ca_name
    if ca_name:
        ca_data = await CARepository.get_by_name(ca_name)
    else:
        ca_data = cas[0]

    if not ca_data:
        raise HTTPException(
            status_code=404,
            detail=f"CA '{ca_name}' not found.",
        )

    # Get CA object for signing
    ca = get_ca_object(ca_data["id"])
    if not ca:
        raise HTTPException(
            status_code=503,
            detail=f"CA '{ca_data['name']}' not loaded. Server may have restarted.",
        )

    # Issue certificate
    try:
        cert = ca.issue_certificate(
            common_name=request.common_name,
            validity_days=request.validity_days,
            san_dns=request.san_dns if request.san_dns else None,
            san_ips=request.san_ips if request.san_ips else None,
            organization=request.organization,
            country=request.country,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Store in database
    cert_data = await CertificateRepository.create(
        serial_number=cert.serial_number,
        common_name=request.common_name,
        certificate_type=request.certificate_type.value,
        certificate_pem=cert.certificate_pem,
        private_key_pem=cert.private_key_pem,
        chain_pem=cert.chain_pem,
        fingerprint_sha256=cert.fingerprint_sha256,
        not_before=cert.not_before,
        not_after=cert.not_after,
        subject_dn=cert.subject_dn,
        issuer_dn=cert.issuer_dn,
        key_algorithm=request.key_algorithm.value,
        ca_id=ca_data["id"],
        san_dns=request.san_dns,
        san_ips=request.san_ips,
    )

    return _cert_dict_to_response(cert_data)


@router.get("", response_model=CertificateListResponse)
async def list_certificates(
    status: Optional[CertificateStatus] = None,
    common_name: Optional[str] = None,
    ca_name: Optional[str] = None,
    expiring_within_days: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List certificates with optional filters."""
    ca_id = None
    if ca_name:
        ca = await CARepository.get_by_name(ca_name)
        if ca:
            ca_id = ca["id"]

    if expiring_within_days:
        certs = await CertificateRepository.get_expiring(expiring_within_days, ca_id)
        return CertificateListResponse(
            certificates=[_cert_dict_to_response(c) for c in certs],
            total=len(certs),
        )

    certs = await CertificateRepository.list_all(
        status=status.value if status else None,
        common_name=common_name,
        ca_id=ca_id,
        limit=limit,
        offset=offset,
    )
    total = await CertificateRepository.count(
        status=status.value if status else None,
        ca_id=ca_id,
    )

    return CertificateListResponse(
        certificates=[_cert_dict_to_response(c) for c in certs],
        total=total,
    )


@router.get("/expiring", response_model=CertificateListResponse)
async def get_expiring_certificates(
    days: int = Query(30, ge=1, le=365),
    ca_name: Optional[str] = None,
):
    """Get certificates expiring within specified days."""
    ca_id = None
    if ca_name:
        ca = await CARepository.get_by_name(ca_name)
        if ca:
            ca_id = ca["id"]

    certs = await CertificateRepository.get_expiring(days, ca_id)

    return CertificateListResponse(
        certificates=[_cert_dict_to_response(c) for c in certs],
        total=len(certs),
    )


@router.get("/{certificate_id}", response_model=CertificateResponse)
async def get_certificate(certificate_id: str):
    """Get certificate details."""
    cert = await CertificateRepository.get_by_id(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return _cert_dict_to_response(cert)


@router.post("/{certificate_id}/revoke")
async def revoke_certificate(
    certificate_id: str,
    request: RevokeCertificateRequest,
):
    """Revoke a certificate."""
    cert = await CertificateRepository.get_by_id(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    if cert["status"] == CertificateStatus.REVOKED.value:
        raise HTTPException(status_code=400, detail="Certificate already revoked")

    await CertificateRepository.revoke(certificate_id, request.reason.value)

    return {"status": "revoked", "certificate_id": certificate_id}


@router.post("/{certificate_id}/renew", response_model=CertificateResponse)
async def renew_certificate(
    certificate_id: str,
    validity_days: int = Query(365, ge=1, le=3650),
):
    """Renew a certificate."""
    cert = await CertificateRepository.get_by_id(certificate_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    # Re-issue with same parameters
    request = IssueCertificateRequest(
        common_name=cert["common_name"],
        validity_days=validity_days,
        san_dns=cert.get("san_dns", []),
        san_ips=cert.get("san_ips", []),
    )

    return await issue_certificate(request, BackgroundTasks())


@router.post("/bulk/issue", response_model=BulkIssueResponse)
async def bulk_issue_certificates(request: BulkIssueRequest):
    """Issue certificates for multiple hosts."""
    issued = []
    failed = []

    for host in request.hosts:
        try:
            cert_request = IssueCertificateRequest(
                common_name=host,
                validity_days=request.validity_days,
                key_algorithm=request.key_algorithm,
                ca_name=request.ca_name,
            )
            cert = await issue_certificate(cert_request, BackgroundTasks())
            issued.append(cert)
        except Exception as e:
            failed.append({"host": host, "error": str(e)})

    return BulkIssueResponse(issued=issued, failed=failed)
