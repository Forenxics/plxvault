"""Certificate Authority management routes."""

from typing import List, Optional
from datetime import datetime
from enum import Enum

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


class CAType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


class KeyAlgorithm(str, Enum):
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"
    HYBRID_ECDSA_MLDSA = "hybrid-ecdsa-mldsa"


class CreateCARequest(BaseModel):
    """Request to create a new CA."""

    name: str = Field(..., min_length=1, max_length=100)
    common_name: str = Field(..., min_length=1, max_length=255)
    organization: Optional[str] = None
    ca_type: CAType = CAType.ROOT
    parent_ca_name: Optional[str] = Field(
        None, description="Parent CA name (required for intermediate)"
    )
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ECDSA_P256
    validity_years: int = Field(10, ge=1, le=30)
    path_length: Optional[int] = Field(None, ge=0, le=10)


class CAResponse(BaseModel):
    """CA information response."""

    id: str
    name: str
    common_name: str
    ca_type: str
    key_algorithm: str
    certificate_pem: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    is_active: bool
    parent_ca_name: Optional[str] = None
    issued_certificates_count: int = 0


class CAListResponse(BaseModel):
    """List of CAs response."""

    cas: List[CAResponse]
    total: int


# In-memory storage for demo (replace with database)
_cas: dict = {}


@router.get("", response_model=CAListResponse)
async def list_cas(
    ca_type: Optional[CAType] = None,
    is_active: Optional[bool] = True,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all Certificate Authorities."""
    # Filter CAs
    cas = list(_cas.values())

    if ca_type:
        cas = [ca for ca in cas if ca.get("ca_type") == ca_type]

    if is_active is not None:
        cas = [ca for ca in cas if ca.get("is_active") == is_active]

    return CAListResponse(
        cas=cas[offset : offset + limit],
        total=len(cas),
    )


@router.post("", response_model=CAResponse)
async def create_ca(request: CreateCARequest):
    """Create a new Certificate Authority."""
    from plxvault import CertificateAuthority, KeyAlgorithm as RustKeyAlgorithm

    if CertificateAuthority is None:
        raise HTTPException(
            status_code=503, detail="Crypto core not available. Build with maturin."
        )

    # Check if CA name already exists
    if request.name in _cas:
        raise HTTPException(status_code=409, detail=f"CA '{request.name}' already exists")

    # Map algorithm
    algo_map = {
        KeyAlgorithm.ECDSA_P256: RustKeyAlgorithm.ecdsa_p256,
        KeyAlgorithm.ECDSA_P384: RustKeyAlgorithm.ecdsa_p384,
        KeyAlgorithm.ED25519: RustKeyAlgorithm.ed25519,
        KeyAlgorithm.ML_DSA_65: RustKeyAlgorithm.ml_dsa_65,
        KeyAlgorithm.HYBRID_ECDSA_MLDSA: RustKeyAlgorithm.hybrid_ecdsa_mldsa,
    }
    algo = algo_map[request.key_algorithm]()

    if request.ca_type == CAType.ROOT:
        # Create root CA
        ca, cert = CertificateAuthority.create_root(
            request.common_name,
            algo,
            request.validity_years,
            request.organization,
        )
    else:
        # Create intermediate CA
        if not request.parent_ca_name:
            raise HTTPException(
                status_code=400, detail="parent_ca_name required for intermediate CA"
            )

        parent = _cas.get(request.parent_ca_name)
        if not parent:
            raise HTTPException(
                status_code=404, detail=f"Parent CA '{request.parent_ca_name}' not found"
            )

        ca, cert = parent["_ca_object"].create_intermediate(
            request.common_name,
            algo,
            request.validity_years,
            request.path_length or 0,
            request.organization,
        )

    # Store CA
    import uuid

    ca_id = str(uuid.uuid4())
    ca_data = {
        "id": ca_id,
        "name": request.name,
        "common_name": cert.subject_dn,
        "ca_type": request.ca_type.value,
        "key_algorithm": request.key_algorithm.value,
        "certificate_pem": cert.certificate_pem,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "not_before": datetime.fromtimestamp(cert.not_before),
        "not_after": datetime.fromtimestamp(cert.not_after),
        "is_active": True,
        "parent_ca_name": request.parent_ca_name,
        "issued_certificates_count": 0,
        "_ca_object": ca,  # Store CA object for signing
        "_private_key_pem": cert.private_key_pem,
    }

    _cas[request.name] = ca_data

    # Return without internal fields
    return CAResponse(**{k: v for k, v in ca_data.items() if not k.startswith("_")})


@router.get("/{ca_name}", response_model=CAResponse)
async def get_ca(ca_name: str):
    """Get CA details."""
    ca = _cas.get(ca_name)
    if not ca:
        raise HTTPException(status_code=404, detail=f"CA '{ca_name}' not found")

    return CAResponse(**{k: v for k, v in ca.items() if not k.startswith("_")})


@router.get("/{ca_name}/certificate")
async def download_ca_certificate(
    ca_name: str,
    include_chain: bool = Query(True),
):
    """Download CA certificate."""
    ca = _cas.get(ca_name)
    if not ca:
        raise HTTPException(status_code=404, detail=f"CA '{ca_name}' not found")

    return {
        "certificate_pem": ca["certificate_pem"],
        "fingerprint_sha256": ca["fingerprint_sha256"],
    }
