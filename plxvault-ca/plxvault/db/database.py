"""SQLite database connection and initialization."""

import aiosqlite
import os
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

# Default database path
DEFAULT_DB_PATH = Path.home() / ".plxvault" / "plxvault.db"

# Global database instance
_db: Optional["Database"] = None


class Database:
    """Async SQLite database wrapper."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Connect to database and initialize schema."""
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row

        # Enable foreign keys
        await self._connection.execute("PRAGMA foreign_keys = ON")

        # Initialize schema
        await self._init_schema()

    async def disconnect(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    @property
    def connection(self) -> aiosqlite.Connection:
        """Get database connection."""
        if not self._connection:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._connection

    async def _init_schema(self) -> None:
        """Initialize database schema."""
        await self._connection.executescript("""
            -- Certificate Authorities table
            CREATE TABLE IF NOT EXISTS certificate_authorities (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                common_name TEXT NOT NULL,
                ca_type TEXT NOT NULL DEFAULT 'root',
                key_algorithm TEXT NOT NULL,
                certificate_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                fingerprint_sha256 TEXT NOT NULL,
                not_before INTEGER NOT NULL,
                not_after INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                parent_ca_id TEXT,
                issued_certificates_count INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (parent_ca_id) REFERENCES certificate_authorities(id)
            );

            -- Certificates table
            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                serial_number TEXT NOT NULL,
                common_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                certificate_type TEXT NOT NULL DEFAULT 'server',
                certificate_pem TEXT NOT NULL,
                private_key_pem TEXT,
                chain_pem TEXT,
                fingerprint_sha256 TEXT NOT NULL,
                not_before INTEGER NOT NULL,
                not_after INTEGER NOT NULL,
                subject_dn TEXT NOT NULL,
                issuer_dn TEXT NOT NULL,
                key_algorithm TEXT NOT NULL,
                ca_id TEXT NOT NULL,
                revocation_date INTEGER,
                revocation_reason TEXT,
                san_dns TEXT,
                san_ips TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id)
            );

            -- Indexes for common queries
            CREATE INDEX IF NOT EXISTS idx_certs_common_name ON certificates(common_name);
            CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status);
            CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certificates(not_after);
            CREATE INDEX IF NOT EXISTS idx_certs_ca_id ON certificates(ca_id);
            CREATE INDEX IF NOT EXISTS idx_cas_name ON certificate_authorities(name);
        """)
        await self._connection.commit()

    @asynccontextmanager
    async def transaction(self):
        """Context manager for transactions."""
        try:
            yield self._connection
            await self._connection.commit()
        except Exception:
            await self._connection.rollback()
            raise


async def init_db(db_path: Optional[str] = None) -> Database:
    """Initialize the global database instance."""
    global _db
    _db = Database(db_path)
    await _db.connect()
    return _db


async def close_db() -> None:
    """Close the global database instance."""
    global _db
    if _db:
        await _db.disconnect()
        _db = None


def get_db() -> Database:
    """Get the global database instance."""
    if not _db:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _db
