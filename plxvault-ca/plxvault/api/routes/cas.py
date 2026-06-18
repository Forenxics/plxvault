"""Certificate Authority management routes."""

from typing import List, Optional
from datetime import datetime
from enum import Enum
import structlog

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from plxvault.db import CARepository

router = APIRouter()
logger = structlog.get_logger()

# In-memory cache for CA signing objects (reconstructed from DB on demand)
_ca_cache: dict = {}


async def load_cas_from_database() -> int:
    """Load all active CAs from database and reconstruct signing objects.

    Returns the number of CAs successfully loaded.
    """
    from plxvault import CertificateAuthority, KeyAlgorithm as RustKeyAlgorithm

    # Map algorithm strings to Rust enum constructors
    algo_map = {
        "ecdsa-p256": RustKeyAlgorithm.ecdsa_p256,
        "ecdsa-p384": RustKeyAlgorithm.ecdsa_p384,
        "ed25519": RustKeyAlgorithm.ed25519,
        "ml-dsa-65": RustKeyAlgorithm.ml_dsa_65,
        "hybrid-ecdsa-mldsa": RustKeyAlgorithm.hybrid_ecdsa_mldsa,
    }

    cas = await CARepository.list_all(is_active=True, limit=1000)
    loaded = 0

    for ca_data in cas:
        try:
            algo_name = ca_data.get("key_algorithm", "ecdsa-p256")
            algo_fn = algo_map.get(algo_name)
            if not algo_fn:
                logger.warning("Unknown algorithm for CA", ca_name=ca_data["name"], algorithm=algo_name)
                continue

            # Reconstruct CA from stored keys
            ca = CertificateAuthority.from_stored(
                ca_data["certificate_pem"],
                ca_data["private_key_pem"],
                algo_fn(),
            )
            _ca_cache[ca_data["id"]] = ca
            loaded += 1
            logger.info("Loaded CA from database", ca_name=ca_data["name"], ca_id=ca_data["id"])
        except Exception as e:
            logger.error("Failed to load CA", ca_name=ca_data["name"], error=str(e))

    return loaded


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
    parent_ca_id: Optional[str] = None
    issued_certificates_count: int = 0


class CAListResponse(BaseModel):
    """List of CAs response."""

    cas: List[CAResponse]
    total: int


def _ca_dict_to_response(ca: dict) -> CAResponse:
    """Convert CA dict to response model."""
    return CAResponse(
        id=ca["id"],
        name=ca["name"],
        common_name=ca["common_name"],
        ca_type=ca["ca_type"],
        key_algorithm=ca["key_algorithm"],
        certificate_pem=ca["certificate_pem"],
        fingerprint_sha256=ca["fingerprint_sha256"],
        not_before=ca["not_before"],
        not_after=ca["not_after"],
        is_active=ca["is_active"],
        parent_ca_id=ca.get("parent_ca_id"),
        issued_certificates_count=ca.get("issued_certificates_count", 0),
    )


@router.get("", response_model=CAListResponse)
async def list_cas(
    ca_type: Optional[CAType] = None,
    is_active: Optional[bool] = True,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all Certificate Authorities."""
    cas = await CARepository.list_all(
        ca_type=ca_type.value if ca_type else None,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )
    total = await CARepository.count(
        ca_type=ca_type.value if ca_type else None,
        is_active=is_active,
    )

    return CAListResponse(
        cas=[_ca_dict_to_response(ca) for ca in cas],
        total=total,
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
    existing = await CARepository.get_by_name(request.name)
    if existing:
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

    parent_ca_id = None

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

        parent = await CARepository.get_by_name(request.parent_ca_name)
        if not parent:
            raise HTTPException(
                status_code=404, detail=f"Parent CA '{request.parent_ca_name}' not found"
            )

        parent_ca_id = parent["id"]

        # Get parent CA object from cache
        if parent["id"] not in _ca_cache:
            raise HTTPException(
                status_code=503,
                detail=f"Parent CA '{request.parent_ca_name}' not loaded. Server may have restarted.",
            )

        parent_ca_obj = _ca_cache[parent["id"]]
        ca, cert = parent_ca_obj.create_intermediate(
            request.common_name,
            algo,
            request.validity_years,
            request.path_length or 0,
            request.organization,
        )

    # Store in database
    ca_data = await CARepository.create(
        name=request.name,
        common_name=cert.subject_dn,
        ca_type=request.ca_type.value,
        key_algorithm=request.key_algorithm.value,
        certificate_pem=cert.certificate_pem,
        private_key_pem=cert.private_key_pem,
        fingerprint_sha256=cert.fingerprint_sha256,
        not_before=cert.not_before,
        not_after=cert.not_after,
        parent_ca_id=parent_ca_id,
    )

    # Cache the CA object for signing
    _ca_cache[ca_data["id"]] = ca

    return _ca_dict_to_response(ca_data)


@router.get("/{ca_name}", response_model=CAResponse)
async def get_ca(ca_name: str):
    """Get CA details."""
    ca = await CARepository.get_by_name(ca_name)
    if not ca:
        raise HTTPException(status_code=404, detail=f"CA '{ca_name}' not found")

    return _ca_dict_to_response(ca)


@router.get("/{ca_name}/certificate")
async def download_ca_certificate(
    ca_name: str,
    include_chain: bool = Query(True),
):
    """Download CA certificate."""
    ca = await CARepository.get_by_name(ca_name)
    if not ca:
        raise HTTPException(status_code=404, detail=f"CA '{ca_name}' not found")

    return {
        "certificate_pem": ca["certificate_pem"],
        "fingerprint_sha256": ca["fingerprint_sha256"],
    }


def get_ca_object(ca_id: str):
    """Get cached CA object for signing."""
    return _ca_cache.get(ca_id)
