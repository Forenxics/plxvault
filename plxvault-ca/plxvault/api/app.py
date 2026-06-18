"""
PlxVault CA - FastAPI Application

AI-native, post-quantum ready Certificate Authority.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from plxvault.api.routes import certificates, cas, health
from plxvault.api.routes.cas import load_cas_from_database
from plxvault.config import settings
from plxvault.db import init_db, close_db

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    logger.info(
        "Starting PlxVault CA",
        version="0.1.0",
        environment=settings.environment,
        database=settings.database_path,
    )

    # Initialize SQLite database
    await init_db(settings.database_path)
    logger.info("Database initialized", path=settings.database_path)

    # Load existing CAs from database
    try:
        loaded_count = await load_cas_from_database()
        logger.info("CAs loaded from database", count=loaded_count)
    except Exception as e:
        logger.warning("Failed to load CAs from database", error=str(e))

    yield

    # Cleanup
    logger.info("Shutting down PlxVault CA")
    await close_db()


app = FastAPI(
    title="PlxVault CA",
    description="""
    ## AI-Native, Post-Quantum Ready Certificate Authority

    PlxVault provides a modern PKI solution with:

    - **AI Integration**: MCP server for natural language certificate management
    - **Post-Quantum Ready**: Support for ML-DSA, hybrid ECDSA+ML-DSA schemes
    - **Modern API**: REST + gRPC interfaces
    - **Short-Lived Certs**: SPIFFE/SPIRE compatible
    - **Event-Driven**: Webhooks for certificate lifecycle events

    ### Quick Start

    ```python
    import httpx

    # Issue a certificate
    response = httpx.post(
        "http://localhost:8000/api/v1/certificates",
        json={"common_name": "server.example.com"}
    )
    cert = response.json()
    print(cert["certificate_pem"])
    ```
    """,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(cas.router, prefix="/api/v1/cas", tags=["Certificate Authorities"])
app.include_router(
    certificates.router, prefix="/api/v1/certificates", tags=["Certificates"]
)


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint."""
    return {
        "name": "PlxVault CA",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }
