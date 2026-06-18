"""Repository classes for database operations."""

import json
import time
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any

from plxvault.db.database import get_db


class CARepository:
    """Repository for Certificate Authority operations."""

    @staticmethod
    async def create(
        name: str,
        common_name: str,
        ca_type: str,
        key_algorithm: str,
        certificate_pem: str,
        private_key_pem: str,
        fingerprint_sha256: str,
        not_before: int,
        not_after: int,
        parent_ca_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new CA."""
        db = get_db()
        ca_id = str(uuid.uuid4())
        now = int(time.time())

        await db.connection.execute(
            """
            INSERT INTO certificate_authorities
            (id, name, common_name, ca_type, key_algorithm, certificate_pem,
             private_key_pem, fingerprint_sha256, not_before, not_after,
             is_active, parent_ca_id, issued_certificates_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?)
            """,
            (
                ca_id, name, common_name, ca_type, key_algorithm, certificate_pem,
                private_key_pem, fingerprint_sha256, not_before, not_after,
                parent_ca_id, now, now
            ),
        )
        await db.connection.commit()

        return await CARepository.get_by_id(ca_id)

    @staticmethod
    async def get_by_id(ca_id: str) -> Optional[Dict[str, Any]]:
        """Get CA by ID."""
        db = get_db()
        cursor = await db.connection.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)
        )
        row = await cursor.fetchone()
        return CARepository._row_to_dict(row) if row else None

    @staticmethod
    async def get_by_name(name: str) -> Optional[Dict[str, Any]]:
        """Get CA by name."""
        db = get_db()
        cursor = await db.connection.execute(
            "SELECT * FROM certificate_authorities WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        return CARepository._row_to_dict(row) if row else None

    @staticmethod
    async def list_all(
        ca_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List all CAs with optional filters."""
        db = get_db()
        query = "SELECT * FROM certificate_authorities WHERE 1=1"
        params = []

        if ca_type:
            query += " AND ca_type = ?"
            params.append(ca_type)

        if is_active is not None:
            query += " AND is_active = ?"
            params.append(1 if is_active else 0)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await db.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [CARepository._row_to_dict(row) for row in rows]

    @staticmethod
    async def count(
        ca_type: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> int:
        """Count CAs with optional filters."""
        db = get_db()
        query = "SELECT COUNT(*) FROM certificate_authorities WHERE 1=1"
        params = []

        if ca_type:
            query += " AND ca_type = ?"
            params.append(ca_type)

        if is_active is not None:
            query += " AND is_active = ?"
            params.append(1 if is_active else 0)

        cursor = await db.connection.execute(query, params)
        row = await cursor.fetchone()
        return row[0]

    @staticmethod
    async def increment_cert_count(ca_id: str) -> None:
        """Increment issued certificates count."""
        db = get_db()
        await db.connection.execute(
            """
            UPDATE certificate_authorities
            SET issued_certificates_count = issued_certificates_count + 1,
                updated_at = ?
            WHERE id = ?
            """,
            (int(time.time()), ca_id),
        )
        await db.connection.commit()

    @staticmethod
    async def update_active_status(ca_id: str, is_active: bool) -> None:
        """Update CA active status."""
        db = get_db()
        await db.connection.execute(
            "UPDATE certificate_authorities SET is_active = ?, updated_at = ? WHERE id = ?",
            (1 if is_active else 0, int(time.time()), ca_id),
        )
        await db.connection.commit()

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        return {
            "id": row["id"],
            "name": row["name"],
            "common_name": row["common_name"],
            "ca_type": row["ca_type"],
            "key_algorithm": row["key_algorithm"],
            "certificate_pem": row["certificate_pem"],
            "private_key_pem": row["private_key_pem"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "not_before": datetime.fromtimestamp(row["not_before"]),
            "not_after": datetime.fromtimestamp(row["not_after"]),
            "is_active": bool(row["is_active"]),
            "parent_ca_id": row["parent_ca_id"],
            "issued_certificates_count": row["issued_certificates_count"],
            "created_at": datetime.fromtimestamp(row["created_at"]),
            "updated_at": datetime.fromtimestamp(row["updated_at"]),
        }


class CertificateRepository:
    """Repository for Certificate operations."""

    @staticmethod
    async def create(
        serial_number: str,
        common_name: str,
        certificate_type: str,
        certificate_pem: str,
        private_key_pem: Optional[str],
        chain_pem: Optional[str],
        fingerprint_sha256: str,
        not_before: int,
        not_after: int,
        subject_dn: str,
        issuer_dn: str,
        key_algorithm: str,
        ca_id: str,
        san_dns: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new certificate."""
        db = get_db()
        cert_id = str(uuid.uuid4())
        now = int(time.time())

        await db.connection.execute(
            """
            INSERT INTO certificates
            (id, serial_number, common_name, status, certificate_type, certificate_pem,
             private_key_pem, chain_pem, fingerprint_sha256, not_before, not_after,
             subject_dn, issuer_dn, key_algorithm, ca_id, san_dns, san_ips, created_at, updated_at)
            VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id, serial_number, common_name, certificate_type, certificate_pem,
                private_key_pem, chain_pem, fingerprint_sha256, not_before, not_after,
                subject_dn, issuer_dn, key_algorithm, ca_id,
                json.dumps(san_dns) if san_dns else None,
                json.dumps(san_ips) if san_ips else None,
                now, now
            ),
        )
        await db.connection.commit()

        # Increment CA cert count
        await CARepository.increment_cert_count(ca_id)

        return await CertificateRepository.get_by_id(cert_id)

    @staticmethod
    async def get_by_id(cert_id: str) -> Optional[Dict[str, Any]]:
        """Get certificate by ID."""
        db = get_db()
        cursor = await db.connection.execute(
            "SELECT * FROM certificates WHERE id = ?", (cert_id,)
        )
        row = await cursor.fetchone()
        return CertificateRepository._row_to_dict(row) if row else None

    @staticmethod
    async def get_by_serial(serial_number: str) -> Optional[Dict[str, Any]]:
        """Get certificate by serial number."""
        db = get_db()
        cursor = await db.connection.execute(
            "SELECT * FROM certificates WHERE serial_number = ?", (serial_number,)
        )
        row = await cursor.fetchone()
        return CertificateRepository._row_to_dict(row) if row else None

    @staticmethod
    async def list_all(
        status: Optional[str] = None,
        common_name: Optional[str] = None,
        ca_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List certificates with optional filters."""
        db = get_db()
        query = "SELECT * FROM certificates WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if common_name:
            query += " AND common_name LIKE ?"
            params.append(f"%{common_name}%")

        if ca_id:
            query += " AND ca_id = ?"
            params.append(ca_id)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await db.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [CertificateRepository._row_to_dict(row) for row in rows]

    @staticmethod
    async def count(
        status: Optional[str] = None,
        ca_id: Optional[str] = None,
    ) -> int:
        """Count certificates with optional filters."""
        db = get_db()
        query = "SELECT COUNT(*) FROM certificates WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if ca_id:
            query += " AND ca_id = ?"
            params.append(ca_id)

        cursor = await db.connection.execute(query, params)
        row = await cursor.fetchone()
        return row[0]

    @staticmethod
    async def get_expiring(days: int, ca_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get certificates expiring within specified days."""
        db = get_db()
        expiry_threshold = int(time.time()) + (days * 86400)

        query = """
            SELECT * FROM certificates
            WHERE status = 'active' AND not_after <= ?
        """
        params = [expiry_threshold]

        if ca_id:
            query += " AND ca_id = ?"
            params.append(ca_id)

        query += " ORDER BY not_after ASC"

        cursor = await db.connection.execute(query, params)
        rows = await cursor.fetchall()
        return [CertificateRepository._row_to_dict(row) for row in rows]

    @staticmethod
    async def revoke(cert_id: str, reason: str) -> Optional[Dict[str, Any]]:
        """Revoke a certificate."""
        db = get_db()
        now = int(time.time())

        await db.connection.execute(
            """
            UPDATE certificates
            SET status = 'revoked', revocation_date = ?, revocation_reason = ?, updated_at = ?
            WHERE id = ?
            """,
            (now, reason, now, cert_id),
        )
        await db.connection.commit()

        return await CertificateRepository.get_by_id(cert_id)

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        return {
            "id": row["id"],
            "serial_number": row["serial_number"],
            "common_name": row["common_name"],
            "status": row["status"],
            "certificate_type": row["certificate_type"],
            "certificate_pem": row["certificate_pem"],
            "private_key_pem": row["private_key_pem"],
            "chain_pem": row["chain_pem"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "not_before": datetime.fromtimestamp(row["not_before"]),
            "not_after": datetime.fromtimestamp(row["not_after"]),
            "subject_dn": row["subject_dn"],
            "issuer_dn": row["issuer_dn"],
            "key_algorithm": row["key_algorithm"],
            "ca_id": row["ca_id"],
            "revocation_date": datetime.fromtimestamp(row["revocation_date"]) if row["revocation_date"] else None,
            "revocation_reason": row["revocation_reason"],
            "san_dns": json.loads(row["san_dns"]) if row["san_dns"] else [],
            "san_ips": json.loads(row["san_ips"]) if row["san_ips"] else [],
            "created_at": datetime.fromtimestamp(row["created_at"]),
            "updated_at": datetime.fromtimestamp(row["updated_at"]),
        }
