#!/usr/bin/env python3
"""
MCP Server for PKI Operations (step-ca backend)

This is a prototype MCP server that enables AI agents to manage certificates
through natural language. It wraps step-ca's CLI for simplicity.

Usage with Claude Code:
  Add to ~/.claude/mcp_settings.json:
  {
    "mcpServers": {
      "pki": {
        "command": "python3",
        "args": ["/path/to/mcp-pki-server/server.py"]
      }
    }
  }
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Any

# MCP Protocol constants
JSONRPC_VERSION = "2.0"

def send_response(id: Any, result: Any = None, error: Any = None):
    """Send a JSON-RPC response."""
    response = {"jsonrpc": JSONRPC_VERSION, "id": id}
    if error:
        response["error"] = error
    else:
        response["result"] = result
    print(json.dumps(response), flush=True)

def send_notification(method: str, params: Any = None):
    """Send a JSON-RPC notification."""
    notification = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params:
        notification["params"] = params
    print(json.dumps(notification), flush=True)

# Tool definitions
TOOLS = [
    {
        "name": "issue_certificate",
        "description": "Issue a new TLS certificate for a hostname. Returns certificate and key paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The hostname/CN for the certificate (e.g., 'myserver.local')"
                },
                "validity_days": {
                    "type": "integer",
                    "description": "Certificate validity in days (default: 365)",
                    "default": 365
                },
                "san": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Subject Alternative Names (additional hostnames/IPs)"
                }
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "list_certificates",
        "description": "List all issued certificates with their expiration dates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "enum": ["all", "expiring_soon", "expired"],
                    "description": "Filter certificates by status",
                    "default": "all"
                },
                "days": {
                    "type": "integer",
                    "description": "For 'expiring_soon', number of days to check (default: 30)",
                    "default": 30
                }
            }
        }
    },
    {
        "name": "revoke_certificate",
        "description": "Revoke a certificate by serial number or hostname.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": {
                    "type": "string",
                    "description": "Certificate serial number"
                },
                "hostname": {
                    "type": "string",
                    "description": "Hostname to revoke (if serial not provided)"
                },
                "reason": {
                    "type": "string",
                    "enum": ["unspecified", "keyCompromise", "superseded", "cessationOfOperation"],
                    "description": "Revocation reason",
                    "default": "unspecified"
                }
            }
        }
    },
    {
        "name": "check_expiration",
        "description": "Check when a certificate expires for a given hostname.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Hostname to check"
                }
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "renew_certificate",
        "description": "Renew an existing certificate before it expires.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Hostname of certificate to renew"
                },
                "validity_days": {
                    "type": "integer",
                    "description": "New validity period in days (default: 365)",
                    "default": 365
                }
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "get_ca_info",
        "description": "Get information about the Certificate Authority (root cert, health, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

def run_step_command(args: list[str]) -> tuple[bool, str]:
    """Run a step CLI command and return (success, output)."""
    try:
        result = subprocess.run(
            ["docker", "exec", "step-cli", "step"] + args,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr or result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "Docker not found. Ensure Docker is running."

def handle_tool_call(name: str, arguments: dict) -> dict:
    """Handle a tool call and return the result."""

    if name == "issue_certificate":
        hostname = arguments["hostname"]
        validity_days = arguments.get("validity_days", 365)
        validity_hours = validity_days * 24

        cert_path = f"/certs/{hostname}.crt"
        key_path = f"/certs/{hostname}.key"

        cmd = [
            "ca", "certificate",
            hostname, cert_path, key_path,
            "--ca-url", "https://step-ca:9000",
            "--root", "/home/step/certs/root_ca.crt",
            "--not-after", f"{validity_hours}h",
            "--force"
        ]

        # Add SANs if provided
        for san in arguments.get("san", []):
            cmd.extend(["--san", san])

        success, output = run_step_command(cmd)

        if success:
            return {
                "success": True,
                "message": f"Certificate issued for {hostname}",
                "certificate": cert_path,
                "key": key_path,
                "expires": (datetime.now() + timedelta(days=validity_days)).isoformat()
            }
        else:
            return {"success": False, "error": output}

    elif name == "list_certificates":
        # In a real implementation, this would query step-ca's database
        # For now, list files in the certs directory
        success, output = run_step_command(["certificate", "inspect", "/certs/*.crt", "--short"])
        return {
            "success": success,
            "certificates": output if success else [],
            "note": "Full implementation would query step-ca database"
        }

    elif name == "revoke_certificate":
        serial = arguments.get("serial")
        reason = arguments.get("reason", "unspecified")

        if not serial:
            return {"success": False, "error": "Serial number required for revocation"}

        cmd = [
            "ca", "revoke",
            serial,
            "--ca-url", "https://step-ca:9000",
            "--root", "/home/step/certs/root_ca.crt",
            "--reason", reason
        ]

        success, output = run_step_command(cmd)
        return {
            "success": success,
            "message": f"Certificate {serial} revoked" if success else output
        }

    elif name == "check_expiration":
        hostname = arguments["hostname"]
        cert_path = f"/certs/{hostname}.crt"

        success, output = run_step_command(["certificate", "inspect", cert_path, "--format", "json"])

        if success:
            try:
                cert_info = json.loads(output)
                not_after = cert_info.get("validity", {}).get("end")
                return {
                    "success": True,
                    "hostname": hostname,
                    "expires": not_after,
                    "details": cert_info
                }
            except json.JSONDecodeError:
                return {"success": True, "raw_output": output}
        else:
            return {"success": False, "error": output}

    elif name == "renew_certificate":
        hostname = arguments["hostname"]
        validity_days = arguments.get("validity_days", 365)

        # Renew by re-issuing
        cert_path = f"/certs/{hostname}.crt"
        key_path = f"/certs/{hostname}.key"

        cmd = [
            "ca", "renew",
            cert_path, key_path,
            "--ca-url", "https://step-ca:9000",
            "--root", "/home/step/certs/root_ca.crt",
            "--force"
        ]

        success, output = run_step_command(cmd)
        return {
            "success": success,
            "message": f"Certificate renewed for {hostname}" if success else output
        }

    elif name == "get_ca_info":
        success, fingerprint = run_step_command(["certificate", "fingerprint", "/home/step/certs/root_ca.crt"])
        success2, inspect = run_step_command(["certificate", "inspect", "/home/step/certs/root_ca.crt", "--short"])

        return {
            "success": success,
            "ca_url": "https://step-ca:9000",
            "fingerprint": fingerprint.strip() if success else None,
            "root_certificate": inspect.strip() if success2 else None
        }

    else:
        return {"error": f"Unknown tool: {name}"}

def handle_request(request: dict):
    """Handle an incoming JSON-RPC request."""
    method = request.get("method")
    id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        send_response(id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "pki-server",
                "version": "0.1.0"
            }
        })

    elif method == "tools/list":
        send_response(id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        result = handle_tool_call(tool_name, arguments)
        send_response(id, {
            "content": [
                {"type": "text", "text": json.dumps(result, indent=2)}
            ]
        })

    elif method == "notifications/initialized":
        pass  # Client initialized, no response needed

    else:
        send_response(id, error={"code": -32601, "message": f"Method not found: {method}"})

def main():
    """Main entry point - read JSON-RPC messages from stdin."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            handle_request(request)
        except json.JSONDecodeError as e:
            send_response(None, error={"code": -32700, "message": f"Parse error: {e}"})

if __name__ == "__main__":
    main()
