#!/usr/bin/env python3
"""
PlxVault MCP Server - AI-native PKI interface

Enables AI agents to manage certificates through natural language.
Integrates with Claude Code and other MCP-compatible AI tools.

Usage:
    python -m plxvault.mcp.server

Or add to Claude Code MCP settings:
    {
        "mcpServers": {
            "plxvault": {
                "command": "plxvault-mcp"
            }
        }
    }
"""

import json
import sys
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

JSONRPC_VERSION = "2.0"

# Tool definitions
TOOLS: List[Dict[str, Any]] = [
    {
        "name": "issue_certificate",
        "description": "Issue a new TLS/SSL certificate for a hostname.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": {
                    "type": "string",
                    "description": "Hostname for the certificate (e.g., 'api.example.com')",
                },
                "type": {
                    "type": "string",
                    "enum": ["server", "client", "code-signing", "email"],
                    "description": "Certificate type",
                    "default": "server",
                },
                "san": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional hostnames/IPs",
                },
                "validity_days": {
                    "type": "integer",
                    "description": "Validity in days",
                    "default": 365,
                },
                "algorithm": {
                    "type": "string",
                    "enum": ["ecdsa-p256", "ed25519", "ml-dsa-65", "hybrid-ecdsa-mldsa"],
                    "description": "Key algorithm",
                    "default": "ecdsa-p256",
                },
            },
            "required": ["common_name"],
        },
    },
    {
        "name": "revoke_certificate",
        "description": "Revoke a certificate by serial number or hostname.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_number": {"type": "string"},
                "common_name": {"type": "string"},
                "reason": {
                    "type": "string",
                    "enum": ["unspecified", "key-compromise", "superseded"],
                    "default": "unspecified",
                },
            },
        },
    },
    {
        "name": "list_certificates",
        "description": "List certificates with optional filters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["active", "revoked", "expired", "all"],
                },
                "common_name": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "get_expiring_certificates",
        "description": "Get certificates expiring within N days.",
        "inputSchema": {
            "type": "object",
            "properties": {"days": {"type": "integer", "default": 30}},
        },
    },
    {
        "name": "create_ca",
        "description": "Create a new Certificate Authority.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "CA identifier"},
                "common_name": {"type": "string", "description": "CA common name"},
                "type": {
                    "type": "string",
                    "enum": ["root", "intermediate"],
                    "default": "root",
                },
                "validity_years": {"type": "integer", "default": 10},
                "algorithm": {
                    "type": "string",
                    "enum": ["ecdsa-p256", "ecdsa-p384", "hybrid-ecdsa-mldsa"],
                    "default": "ecdsa-p384",
                },
            },
            "required": ["name", "common_name"],
        },
    },
    {
        "name": "list_cas",
        "description": "List all Certificate Authorities.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bulk_issue",
        "description": "Issue certificates for multiple hosts at once.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hostnames",
                },
                "validity_days": {"type": "integer", "default": 365},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "health_check",
        "description": "Check PlxVault CA system health.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServer:
    """MCP Server for PlxVault CA."""

    def __init__(self):
        self.initialized = False
        # Import API routes for in-process calls
        try:
            from plxvault.api.routes.cas import _cas
            from plxvault.api.routes.certificates import _certificates

            self._cas = _cas
            self._certificates = _certificates
        except ImportError:
            self._cas = {}
            self._certificates = {}

    def send_response(
        self, id: Any, result: Optional[Any] = None, error: Optional[Any] = None
    ):
        """Send JSON-RPC response."""
        response: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": id}
        if error:
            response["error"] = error
        else:
            response["result"] = result
        print(json.dumps(response), flush=True)

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a tool call."""

        if name == "issue_certificate":
            return await self._issue_certificate(arguments)
        elif name == "revoke_certificate":
            return await self._revoke_certificate(arguments)
        elif name == "list_certificates":
            return await self._list_certificates(arguments)
        elif name == "get_expiring_certificates":
            return await self._get_expiring_certificates(arguments)
        elif name == "create_ca":
            return await self._create_ca(arguments)
        elif name == "list_cas":
            return await self._list_cas(arguments)
        elif name == "bulk_issue":
            return await self._bulk_issue(arguments)
        elif name == "health_check":
            return await self._health_check(arguments)
        else:
            return {"error": f"Unknown tool: {name}"}

    async def _issue_certificate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a certificate."""
        try:
            from plxvault import CertificateAuthority, KeyAlgorithm

            if not self._cas:
                return {
                    "success": False,
                    "error": "No CA available. Create one first with create_ca.",
                }

            # Get first CA
            ca_name = list(self._cas.keys())[0]
            ca_data = self._cas[ca_name]
            ca = ca_data["_ca_object"]

            cert = ca.issue_certificate(
                common_name=args["common_name"],
                validity_days=args.get("validity_days", 365),
                san_dns=args.get("san"),
            )

            return {
                "success": True,
                "certificate": {
                    "serial_number": cert.serial_number,
                    "common_name": args["common_name"],
                    "expires": datetime.fromtimestamp(cert.not_after).isoformat(),
                    "fingerprint": cert.fingerprint_sha256,
                    "issuer": cert.issuer_dn,
                },
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _revoke_certificate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a certificate."""
        serial = args.get("serial_number")
        cn = args.get("common_name")

        # Find certificate
        for cert_id, cert in self._certificates.items():
            if serial and cert["serial_number"] == serial:
                cert["status"] = "revoked"
                cert["revocation_date"] = datetime.utcnow().isoformat()
                cert["revocation_reason"] = args.get("reason", "unspecified")
                return {"success": True, "revoked": serial}
            if cn and cert["common_name"] == cn:
                cert["status"] = "revoked"
                cert["revocation_date"] = datetime.utcnow().isoformat()
                cert["revocation_reason"] = args.get("reason", "unspecified")
                return {"success": True, "revoked": cert["serial_number"]}

        return {"success": False, "error": "Certificate not found"}

    async def _list_certificates(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List certificates."""
        certs = list(self._certificates.values())
        status = args.get("status")
        cn = args.get("common_name")
        limit = args.get("limit", 50)

        if status and status != "all":
            certs = [c for c in certs if c["status"] == status]
        if cn:
            certs = [c for c in certs if cn.lower() in c["common_name"].lower()]

        return {
            "success": True,
            "count": len(certs[:limit]),
            "certificates": [
                {
                    "serial_number": c["serial_number"],
                    "common_name": c["common_name"],
                    "status": c["status"],
                    "expires": c["not_after"].isoformat()
                    if isinstance(c["not_after"], datetime)
                    else c["not_after"],
                }
                for c in certs[:limit]
            ],
        }

    async def _get_expiring_certificates(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get expiring certificates."""
        from datetime import timedelta

        days = args.get("days", 30)
        threshold = datetime.utcnow() + timedelta(days=days)

        expiring = []
        for cert in self._certificates.values():
            not_after = cert["not_after"]
            if isinstance(not_after, str):
                not_after = datetime.fromisoformat(not_after)
            if not_after <= threshold and cert["status"] == "active":
                expiring.append(
                    {
                        "serial_number": cert["serial_number"],
                        "common_name": cert["common_name"],
                        "expires": not_after.isoformat(),
                        "days_until_expiry": (not_after - datetime.utcnow()).days,
                    }
                )

        return {
            "success": True,
            "days": days,
            "count": len(expiring),
            "certificates": expiring,
            "action_required": len(expiring) > 0,
        }

    async def _create_ca(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Create a CA."""
        try:
            from plxvault import CertificateAuthority, KeyAlgorithm

            if CertificateAuthority is None:
                return {
                    "success": False,
                    "error": "Crypto core not available. Build with: maturin develop",
                }

            # Map algorithm
            algo_map = {
                "ecdsa-p256": KeyAlgorithm.ecdsa_p256,
                "ecdsa-p384": KeyAlgorithm.ecdsa_p384,
                "ed25519": KeyAlgorithm.ed25519,
                "hybrid-ecdsa-mldsa": KeyAlgorithm.hybrid_ecdsa_mldsa,
            }
            algo_name = args.get("algorithm", "ecdsa-p384")
            algo = algo_map.get(algo_name, KeyAlgorithm.ecdsa_p384)()

            ca, cert = CertificateAuthority.create_root(
                args["common_name"],
                algo,
                args.get("validity_years", 10),
            )

            # Store CA
            self._cas[args["name"]] = {
                "name": args["name"],
                "common_name": cert.subject_dn,
                "fingerprint": cert.fingerprint_sha256,
                "expires": datetime.fromtimestamp(cert.not_after).isoformat(),
                "_ca_object": ca,
            }

            return {
                "success": True,
                "ca": {
                    "name": args["name"],
                    "common_name": cert.subject_dn,
                    "fingerprint": cert.fingerprint_sha256,
                    "expires": datetime.fromtimestamp(cert.not_after).isoformat(),
                },
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _list_cas(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List CAs."""
        return {
            "success": True,
            "count": len(self._cas),
            "cas": [
                {
                    "name": ca.get("name"),
                    "common_name": ca.get("common_name"),
                    "fingerprint": ca.get("fingerprint"),
                }
                for ca in self._cas.values()
            ],
        }

    async def _bulk_issue(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Bulk issue certificates."""
        hosts = args.get("hosts", [])
        validity_days = args.get("validity_days", 365)

        issued = []
        failed = []

        for host in hosts:
            result = await self._issue_certificate(
                {"common_name": host, "validity_days": validity_days}
            )
            if result.get("success"):
                issued.append(result["certificate"])
            else:
                failed.append({"host": host, "error": result.get("error")})

        return {
            "success": True,
            "issued_count": len(issued),
            "failed_count": len(failed),
            "issued": issued,
            "failed": failed,
        }

    async def _health_check(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Health check."""
        try:
            from plxvault import CertificateAuthority

            crypto_available = CertificateAuthority is not None
        except ImportError:
            crypto_available = False

        return {
            "success": True,
            "status": "healthy" if crypto_available else "degraded",
            "version": "0.1.0",
            "crypto_core": "available" if crypto_available else "not built",
            "cas_count": len(self._cas),
            "certificates_count": len(self._certificates),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def handle_request(self, request: Dict[str, Any]):
        """Handle an incoming JSON-RPC request."""
        method = request.get("method")
        id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            self.send_response(
                id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "plxvault-ca",
                        "version": "0.1.0",
                        "description": "AI-native PKI - Issue, revoke, and manage certificates",
                    },
                },
            )

        elif method == "tools/list":
            self.send_response(id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            result = await self.handle_tool_call(tool_name, arguments)
            self.send_response(
                id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps(result, indent=2, default=str)}
                    ]
                },
            )

        elif method == "notifications/initialized":
            self.initialized = True

        else:
            self.send_response(
                id, error={"code": -32601, "message": f"Method not found: {method}"}
            )

    async def run(self):
        """Run the MCP server."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                await self.handle_request(request)
            except json.JSONDecodeError as e:
                self.send_response(
                    None, error={"code": -32700, "message": f"Parse error: {e}"}
                )


def main():
    """Entry point for MCP server."""
    server = MCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
