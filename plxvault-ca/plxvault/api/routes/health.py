"""Health check endpoints."""

from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def health_check() -> Dict[str, Any]:
    """Check service health."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0",
        "components": {
            "api": "healthy",
            "crypto_core": "healthy",
        },
    }


@router.get("/ready")
async def readiness_check() -> Dict[str, str]:
    """Kubernetes readiness probe."""
    return {"status": "ready"}


@router.get("/live")
async def liveness_check() -> Dict[str, str]:
    """Kubernetes liveness probe."""
    return {"status": "alive"}
