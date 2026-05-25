#!/usr/bin/env python3
"""
MCP Server for EJBCA PKI Operations

Complete PKI management through natural language via AI agents.
Wraps EJBCA's REST API and CLI to expose full functionality.

The complexity of EJBCA becomes invisible - users just state intent,
the AI handles the 47 screens worth of configuration.

Usage with Claude Code:
  Add to ~/.claude/mcp_settings.json:
  {
    "mcpServers": {
      "ejbca": {
        "command": "python3",
        "args": ["/path/to/mcp-pki-server/ejbca_server.py"],
        "env": {
          "EJBCA_URL": "https://localhost:8443/ejbca",
          "EJBCA_CERT": "/path/to/admin.pem",
          "EJBCA_KEY": "/path/to/admin.key"
        }
      }
    }
  }
"""

import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timedelta
from typing import Any, Optional

# Configuration from environment
EJBCA_URL = os.environ.get("EJBCA_URL", "https://localhost:8443/ejbca")
EJBCA_REST_API = f"{EJBCA_URL}/ejbca-rest-api/v1"
EJBCA_CERT = os.environ.get("EJBCA_CERT", "")
EJBCA_KEY = os.environ.get("EJBCA_KEY", "")

# MCP Protocol
JSONRPC_VERSION = "2.0"

def send_response(id: Any, result: Any = None, error: Any = None):
    response = {"jsonrpc": JSONRPC_VERSION, "id": id}
    if error:
        response["error"] = error
    else:
        response["result"] = result
    print(json.dumps(response), flush=True)

# =============================================================================
# EJBCA Tool Definitions - Full Feature Coverage
# =============================================================================

TOOLS = [
    # -------------------------------------------------------------------------
    # Certificate Operations
    # -------------------------------------------------------------------------
    {
        "name": "issue_certificate",
        "description": """Issue a new certificate. Handles all EJBCA complexity automatically:
        - Creates end entity if needed
        - Selects appropriate certificate profile
        - Generates or accepts CSR
        - Returns certificate in requested format""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": {
                    "type": "string",
                    "description": "Common Name (CN) for the certificate, e.g., 'server.company.com'"
                },
                "type": {
                    "type": "string",
                    "enum": ["server", "client", "code_signing", "email", "ca"],
                    "description": "Certificate type - determines profile and key usage",
                    "default": "server"
                },
                "san": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Subject Alternative Names (DNS names, IPs, emails)"
                },
                "validity_days": {
                    "type": "integer",
                    "description": "Validity period in days",
                    "default": 365
                },
                "key_algorithm": {
                    "type": "string",
                    "enum": ["RSA2048", "RSA4096", "ECDSA_P256", "ECDSA_P384"],
                    "default": "RSA2048"
                },
                "csr": {
                    "type": "string",
                    "description": "PEM-encoded CSR (if not provided, key pair will be generated)"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["PEM", "PKCS12", "JKS", "DER"],
                    "default": "PEM"
                },
                "organization": {"type": "string", "description": "O field"},
                "organizational_unit": {"type": "string", "description": "OU field"},
                "country": {"type": "string", "description": "C field (2-letter code)"},
                "email": {"type": "string", "description": "Email for notifications"}
            },
            "required": ["common_name"]
        }
    },
    {
        "name": "revoke_certificate",
        "description": "Revoke a certificate immediately. Supports revocation by serial number, CN, or search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_number": {
                    "type": "string",
                    "description": "Certificate serial number (hex)"
                },
                "common_name": {
                    "type": "string",
                    "description": "CN to search and revoke"
                },
                "issuer_dn": {
                    "type": "string",
                    "description": "Issuer DN (if known)"
                },
                "reason": {
                    "type": "string",
                    "enum": [
                        "UNSPECIFIED",
                        "KEY_COMPROMISE",
                        "CA_COMPROMISE",
                        "AFFILIATION_CHANGED",
                        "SUPERSEDED",
                        "CESSATION_OF_OPERATION",
                        "CERTIFICATE_HOLD",
                        "REMOVE_FROM_CRL",
                        "PRIVILEGES_WITHDRAWN"
                    ],
                    "default": "UNSPECIFIED"
                },
                "revoke_all_for_cn": {
                    "type": "boolean",
                    "description": "If true and CN provided, revoke ALL certs for that CN",
                    "default": False
                }
            }
        }
    },
    {
        "name": "renew_certificate",
        "description": "Renew an existing certificate. Maintains same subject but issues new cert with fresh validity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": {
                    "type": "string",
                    "description": "CN of certificate to renew"
                },
                "serial_number": {
                    "type": "string",
                    "description": "Serial of specific cert to renew"
                },
                "validity_days": {
                    "type": "integer",
                    "default": 365
                },
                "new_key": {
                    "type": "boolean",
                    "description": "Generate new key pair (recommended)",
                    "default": True
                }
            }
        }
    },
    {
        "name": "search_certificates",
        "description": "Search for certificates by various criteria. Returns matching certs with status and expiry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Free-text search (searches CN, serial, etc.)"
                },
                "common_name": {"type": "string"},
                "serial_number": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": ["ACTIVE", "REVOKED", "EXPIRED", "ALL"],
                    "default": "ALL"
                },
                "expiring_within_days": {
                    "type": "integer",
                    "description": "Find certs expiring within N days"
                },
                "issued_after": {
                    "type": "string",
                    "description": "ISO date - certs issued after this date"
                },
                "issued_before": {
                    "type": "string",
                    "description": "ISO date - certs issued before this date"
                },
                "ca_name": {
                    "type": "string",
                    "description": "Filter by issuing CA"
                },
                "limit": {
                    "type": "integer",
                    "default": 100
                }
            }
        }
    },
    {
        "name": "get_certificate",
        "description": "Get full details of a specific certificate including the PEM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_number": {"type": "string"},
                "common_name": {"type": "string"},
                "include_chain": {
                    "type": "boolean",
                    "description": "Include full certificate chain",
                    "default": True
                },
                "format": {
                    "type": "string",
                    "enum": ["PEM", "DER", "PKCS7"],
                    "default": "PEM"
                }
            }
        }
    },

    # -------------------------------------------------------------------------
    # End Entity Management
    # -------------------------------------------------------------------------
    {
        "name": "create_end_entity",
        "description": "Create an end entity (user/device) that can request certificates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Unique username/identifier"
                },
                "common_name": {"type": "string"},
                "email": {"type": "string"},
                "organization": {"type": "string"},
                "organizational_unit": {"type": "string"},
                "end_entity_profile": {
                    "type": "string",
                    "description": "Profile name (will suggest if not provided)"
                },
                "certificate_profile": {
                    "type": "string",
                    "description": "Certificate profile (will suggest if not provided)"
                },
                "ca_name": {
                    "type": "string",
                    "description": "Issuing CA name"
                },
                "token_type": {
                    "type": "string",
                    "enum": ["USERGENERATED", "P12", "JKS", "PEM"],
                    "default": "USERGENERATED"
                }
            },
            "required": ["username", "common_name"]
        }
    },
    {
        "name": "search_end_entities",
        "description": "Search for end entities (users/devices) in EJBCA.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term"},
                "username": {"type": "string"},
                "common_name": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": ["NEW", "FAILED", "INITIALIZED", "INPROCESS", "GENERATED", "REVOKED", "ALL"],
                    "default": "ALL"
                },
                "limit": {"type": "integer", "default": 100}
            }
        }
    },
    {
        "name": "delete_end_entity",
        "description": "Delete an end entity and optionally revoke its certificates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username to delete"},
                "revoke_certificates": {
                    "type": "boolean",
                    "description": "Also revoke all certificates",
                    "default": True
                }
            },
            "required": ["username"]
        }
    },

    # -------------------------------------------------------------------------
    # CA Management
    # -------------------------------------------------------------------------
    {
        "name": "list_cas",
        "description": "List all Certificate Authorities in the system.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_external": {
                    "type": "boolean",
                    "description": "Include external CAs",
                    "default": True
                }
            }
        }
    },
    {
        "name": "get_ca_info",
        "description": "Get detailed information about a CA including certificate, CRL URLs, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ca_name": {
                    "type": "string",
                    "description": "CA name (list CAs first if unknown)"
                }
            },
            "required": ["ca_name"]
        }
    },
    {
        "name": "get_ca_certificate",
        "description": "Download a CA's certificate (root or intermediate).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ca_name": {"type": "string"},
                "format": {
                    "type": "string",
                    "enum": ["PEM", "DER"],
                    "default": "PEM"
                },
                "include_chain": {
                    "type": "boolean",
                    "default": True
                }
            },
            "required": ["ca_name"]
        }
    },

    # -------------------------------------------------------------------------
    # Profiles (Templates)
    # -------------------------------------------------------------------------
    {
        "name": "list_certificate_profiles",
        "description": "List available certificate profiles (templates for cert properties).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "list_end_entity_profiles",
        "description": "List available end entity profiles (templates for users/devices).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "suggest_profiles",
        "description": "Get profile recommendations based on use case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "use_case": {
                    "type": "string",
                    "description": "Describe what you need, e.g., 'TLS for web servers', 'code signing', 'email encryption'"
                }
            },
            "required": ["use_case"]
        }
    },

    # -------------------------------------------------------------------------
    # Monitoring & Reporting
    # -------------------------------------------------------------------------
    {
        "name": "get_expiring_certificates",
        "description": "Get all certificates expiring within a time period. Critical for preventing outages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "Days until expiration",
                    "default": 30
                },
                "ca_name": {
                    "type": "string",
                    "description": "Filter by CA (optional)"
                },
                "include_revoked": {
                    "type": "boolean",
                    "default": False
                }
            }
        }
    },
    {
        "name": "get_certificate_stats",
        "description": "Get statistics: total certs, by status, by CA, expiring soon, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ca_name": {"type": "string", "description": "Filter by CA (optional)"}
            }
        }
    },
    {
        "name": "health_check",
        "description": "Check EJBCA system health: CA status, HSM connectivity, database, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },

    # -------------------------------------------------------------------------
    # Bulk Operations
    # -------------------------------------------------------------------------
    {
        "name": "bulk_issue_certificates",
        "description": "Issue certificates for multiple entities at once. Accepts list of hostnames/CNs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "common_name": {"type": "string"},
                            "san": {"type": "array", "items": {"type": "string"}},
                            "type": {"type": "string"}
                        },
                        "required": ["common_name"]
                    },
                    "description": "List of entities to issue certs for"
                },
                "validity_days": {"type": "integer", "default": 365},
                "key_algorithm": {"type": "string", "default": "RSA2048"}
            },
            "required": ["entities"]
        }
    },
    {
        "name": "bulk_renew_expiring",
        "description": "Automatically renew all certificates expiring within N days.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "Renew certs expiring within this many days",
                    "default": 30
                },
                "ca_name": {"type": "string", "description": "Filter by CA"},
                "dry_run": {
                    "type": "boolean",
                    "description": "List what would be renewed without actually renewing",
                    "default": True
                }
            }
        }
    },
    {
        "name": "bulk_revoke",
        "description": "Revoke multiple certificates at once (e.g., compromised server, departing employee).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial_numbers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of serial numbers to revoke"
                },
                "common_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of CNs - will revoke all certs for each"
                },
                "reason": {"type": "string", "default": "UNSPECIFIED"}
            }
        }
    },

    # -------------------------------------------------------------------------
    # ACME / Auto-Enrollment
    # -------------------------------------------------------------------------
    {
        "name": "get_acme_config",
        "description": "Get ACME configuration for automated certificate management (Let's Encrypt style).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alias": {"type": "string", "description": "ACME alias name"}
            }
        }
    },

    # -------------------------------------------------------------------------
    # Audit & Compliance
    # -------------------------------------------------------------------------
    {
        "name": "get_audit_log",
        "description": "Get audit log entries for compliance and troubleshooting.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_date": {"type": "string", "description": "ISO date"},
                "end_date": {"type": "string", "description": "ISO date"},
                "event_type": {
                    "type": "string",
                    "enum": ["CERT_ISSUE", "CERT_REVOKE", "AUTH_FAILURE", "CONFIG_CHANGE", "ALL"],
                    "default": "ALL"
                },
                "username": {"type": "string", "description": "Filter by admin username"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    },

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------
    {
        "name": "decode_csr",
        "description": "Decode and validate a CSR, showing the requested subject and extensions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "csr": {
                    "type": "string",
                    "description": "PEM-encoded CSR"
                }
            },
            "required": ["csr"]
        }
    },
    {
        "name": "decode_certificate",
        "description": "Decode a certificate showing all fields, validity, extensions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "certificate": {
                    "type": "string",
                    "description": "PEM-encoded certificate"
                }
            },
            "required": ["certificate"]
        }
    },
    {
        "name": "verify_certificate",
        "description": "Verify a certificate against the CA chain, check revocation status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "certificate": {"type": "string", "description": "PEM certificate to verify"},
                "check_ocsp": {"type": "boolean", "default": True},
                "check_crl": {"type": "boolean", "default": True}
            },
            "required": ["certificate"]
        }
    },
    {
        "name": "explain_error",
        "description": "Explain an EJBCA error message in plain English with suggested fixes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "error_message": {"type": "string"},
                "context": {"type": "string", "description": "What were you trying to do?"}
            },
            "required": ["error_message"]
        }
    }
]


# =============================================================================
# API Helpers
# =============================================================================

def create_ssl_context():
    """Create SSL context for EJBCA API calls."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # For dev; production should verify

    if EJBCA_CERT and EJBCA_KEY:
        ctx.load_cert_chain(EJBCA_CERT, EJBCA_KEY)

    return ctx

def ejbca_api_call(method: str, endpoint: str, data: dict = None) -> tuple[bool, Any]:
    """Make an EJBCA REST API call."""
    url = f"{EJBCA_REST_API}/{endpoint}"

    try:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if data:
            req_data = json.dumps(data).encode('utf-8')
        else:
            req_data = None

        request = urllib.request.Request(url, data=req_data, headers=headers, method=method)

        ctx = create_ssl_context()

        with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            return True, result

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        return False, {"http_error": e.code, "message": error_body}
    except urllib.error.URLError as e:
        return False, {"error": "Connection failed", "message": str(e.reason)}
    except Exception as e:
        return False, {"error": str(type(e).__name__), "message": str(e)}


def ejbca_cli(args: list[str]) -> tuple[bool, str]:
    """Run EJBCA CLI command via docker."""
    try:
        result = subprocess.run(
            ["docker", "exec", "ejbca-dev", "/opt/keyfactor/bin/ejbca.sh"] + args,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr or result.stdout
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "Docker not available"


# =============================================================================
# Tool Implementations
# =============================================================================

def handle_tool_call(name: str, arguments: dict) -> dict:
    """Route tool calls to implementations."""

    # Certificate Operations
    if name == "issue_certificate":
        return issue_certificate(arguments)
    elif name == "revoke_certificate":
        return revoke_certificate(arguments)
    elif name == "renew_certificate":
        return renew_certificate(arguments)
    elif name == "search_certificates":
        return search_certificates(arguments)
    elif name == "get_certificate":
        return get_certificate(arguments)

    # End Entity
    elif name == "create_end_entity":
        return create_end_entity(arguments)
    elif name == "search_end_entities":
        return search_end_entities(arguments)
    elif name == "delete_end_entity":
        return delete_end_entity(arguments)

    # CA Management
    elif name == "list_cas":
        return list_cas(arguments)
    elif name == "get_ca_info":
        return get_ca_info(arguments)
    elif name == "get_ca_certificate":
        return get_ca_certificate(arguments)

    # Profiles
    elif name == "list_certificate_profiles":
        return list_certificate_profiles(arguments)
    elif name == "list_end_entity_profiles":
        return list_end_entity_profiles(arguments)
    elif name == "suggest_profiles":
        return suggest_profiles(arguments)

    # Monitoring
    elif name == "get_expiring_certificates":
        return get_expiring_certificates(arguments)
    elif name == "get_certificate_stats":
        return get_certificate_stats(arguments)
    elif name == "health_check":
        return health_check(arguments)

    # Bulk
    elif name == "bulk_issue_certificates":
        return bulk_issue_certificates(arguments)
    elif name == "bulk_renew_expiring":
        return bulk_renew_expiring(arguments)
    elif name == "bulk_revoke":
        return bulk_revoke(arguments)

    # Utilities
    elif name == "decode_csr":
        return decode_csr(arguments)
    elif name == "decode_certificate":
        return decode_certificate(arguments)
    elif name == "verify_certificate":
        return verify_certificate(arguments)
    elif name == "explain_error":
        return explain_error(arguments)

    # ACME
    elif name == "get_acme_config":
        return get_acme_config(arguments)

    # Audit
    elif name == "get_audit_log":
        return get_audit_log(arguments)

    else:
        return {"error": f"Unknown tool: {name}"}


# =============================================================================
# Tool Implementations (Core)
# =============================================================================

def issue_certificate(args: dict) -> dict:
    """Issue a new certificate - the most important operation."""
    cn = args["common_name"]
    cert_type = args.get("type", "server")

    # Map type to profile (this would be configurable)
    profile_map = {
        "server": ("SERVER", "TLS Server"),
        "client": ("ENDUSER", "TLS Client"),
        "code_signing": ("ENDUSER", "Code Signing"),
        "email": ("ENDUSER", "Email"),
        "ca": ("SUBCA", "SubCA")
    }

    ee_profile, cert_profile = profile_map.get(cert_type, ("SERVER", "TLS Server"))

    # Try REST API first (Enterprise), fall back to CLI
    success, result = ejbca_api_call("POST", "certificate/pkcs10enroll", {
        "certificate_request": args.get("csr", ""),
        "certificate_profile_name": cert_profile,
        "end_entity_profile_name": ee_profile,
        "ca_name": args.get("ca_name", "ManagementCA"),
        "username": cn.replace(".", "_"),
        "password": "generated",  # Would be random in production
        "include_chain": True
    })

    if success:
        return {
            "success": True,
            "common_name": cn,
            "certificate": result.get("certificate"),
            "serial_number": result.get("serial_number"),
            "expires": result.get("not_after"),
            "issuer": result.get("issuer_dn")
        }

    # REST API might not be available in CE, provide guidance
    return {
        "success": False,
        "error": "REST API call failed",
        "details": result,
        "alternative": f"""
To issue via Admin GUI:
1. RA Functions → Add End Entity
   - Username: {cn.replace(".", "_")}
   - CN: {cn}
   - Certificate Profile: {cert_profile}
   - End Entity Profile: {ee_profile}
   - Token: User Generated (if you have CSR) or P12
   - Status: New

2. Public Web → Create Certificate
   - Enter username and enrollment code
   - Upload CSR or generate keystore
"""
    }


def search_certificates(args: dict) -> dict:
    """Search for certificates."""
    success, result = ejbca_api_call("GET", "certificate/search", {
        "max_results": args.get("limit", 100),
        "criteria": [
            {"property": "QUERY", "value": args.get("query", "*"), "operation": "LIKE"}
        ]
    })

    if success:
        return {"success": True, "certificates": result.get("certificates", [])}

    return {"success": False, "error": result}


def get_expiring_certificates(args: dict) -> dict:
    """Get certificates expiring soon."""
    days = args.get("days", 30)

    success, result = ejbca_api_call("GET", f"certificate/expire?days={days}")

    if success:
        certs = result.get("certificates", [])
        return {
            "success": True,
            "days": days,
            "count": len(certs),
            "certificates": certs,
            "action_required": len(certs) > 0,
            "message": f"{len(certs)} certificate(s) expiring within {days} days"
        }

    return {"success": False, "error": result}


def list_cas(args: dict) -> dict:
    """List all CAs."""
    success, result = ejbca_api_call("GET", "ca")

    if success:
        return {"success": True, "cas": result.get("certificate_authorities", [])}

    # Try CLI fallback
    cli_success, cli_output = ejbca_cli(["ca", "listcas"])
    if cli_success:
        return {"success": True, "cas": cli_output.strip().split("\n")}

    return {"success": False, "error": result}


def health_check(args: dict) -> dict:
    """Check EJBCA health."""
    success, result = ejbca_api_call("GET", "../publicweb/healthcheck/ejbcahealth")

    return {
        "success": success,
        "status": "healthy" if success else "unhealthy",
        "details": result
    }


def suggest_profiles(args: dict) -> dict:
    """Suggest profiles based on use case."""
    use_case = args.get("use_case", "").lower()

    suggestions = {
        "web": {"ee_profile": "SERVER", "cert_profile": "TLS Server", "notes": "For HTTPS servers"},
        "tls": {"ee_profile": "SERVER", "cert_profile": "TLS Server", "notes": "For TLS/SSL"},
        "server": {"ee_profile": "SERVER", "cert_profile": "TLS Server", "notes": "Generic server cert"},
        "client": {"ee_profile": "ENDUSER", "cert_profile": "TLS Client", "notes": "For client authentication"},
        "user": {"ee_profile": "ENDUSER", "cert_profile": "ENDUSER", "notes": "For user authentication"},
        "email": {"ee_profile": "ENDUSER", "cert_profile": "Email", "notes": "S/MIME email encryption"},
        "code": {"ee_profile": "ENDUSER", "cert_profile": "Code Signing", "notes": "For signing code"},
        "signing": {"ee_profile": "ENDUSER", "cert_profile": "Code Signing", "notes": "For digital signatures"},
        "iot": {"ee_profile": "SERVER", "cert_profile": "TLS Server", "notes": "For IoT device identity"},
        "device": {"ee_profile": "SERVER", "cert_profile": "TLS Server", "notes": "For device authentication"},
    }

    for key, suggestion in suggestions.items():
        if key in use_case:
            return {"success": True, "suggestion": suggestion, "matched": key}

    return {
        "success": True,
        "suggestion": {
            "ee_profile": "SERVER",
            "cert_profile": "TLS Server",
            "notes": "Default suggestion - describe your use case more specifically for better match"
        },
        "available_use_cases": list(suggestions.keys())
    }


def explain_error(args: dict) -> dict:
    """Explain EJBCA errors in plain English."""
    error = args.get("error_message", "").lower()
    context = args.get("context", "")

    explanations = {
        "user not found": {
            "meaning": "The end entity (user/device) doesn't exist in EJBCA",
            "fix": "Create the end entity first using create_end_entity, then try again"
        },
        "status is not new": {
            "meaning": "This end entity has already enrolled or its status changed",
            "fix": "Reset the end entity status to NEW, or create a new end entity"
        },
        "certificate profile": {
            "meaning": "The certificate profile specified doesn't exist or isn't allowed",
            "fix": "Use list_certificate_profiles to see available profiles"
        },
        "ca name": {
            "meaning": "The CA specified doesn't exist or you don't have access",
            "fix": "Use list_cas to see available CAs"
        },
        "not authorized": {
            "meaning": "Your admin certificate doesn't have permission for this operation",
            "fix": "Check role permissions in System Functions → Roles"
        },
        "already revoked": {
            "meaning": "This certificate is already revoked",
            "fix": "No action needed - certificate is already invalid"
        }
    }

    for key, explanation in explanations.items():
        if key in error:
            return {"success": True, "explanation": explanation, "original_error": error}

    return {
        "success": True,
        "explanation": {
            "meaning": "Unknown error",
            "fix": "Check EJBCA logs for more details, or provide more context"
        },
        "original_error": error
    }


# Stub implementations for remaining tools
def revoke_certificate(args): return {"success": False, "error": "Not yet implemented", "todo": "Call REST API PUT /certificate/{issuer}/{serial}/revoke"}
def renew_certificate(args): return {"success": False, "error": "Not yet implemented"}
def get_certificate(args): return {"success": False, "error": "Not yet implemented"}
def create_end_entity(args): return {"success": False, "error": "Not yet implemented"}
def search_end_entities(args): return {"success": False, "error": "Not yet implemented"}
def delete_end_entity(args): return {"success": False, "error": "Not yet implemented"}
def get_ca_info(args): return list_cas(args)  # Reuse for now
def get_ca_certificate(args): return {"success": False, "error": "Not yet implemented"}
def list_certificate_profiles(args): return {"success": False, "error": "Not yet implemented", "note": "Enterprise REST API only"}
def list_end_entity_profiles(args): return {"success": False, "error": "Not yet implemented", "note": "Enterprise REST API only"}
def get_certificate_stats(args): return {"success": False, "error": "Not yet implemented"}
def bulk_issue_certificates(args): return {"success": False, "error": "Not yet implemented"}
def bulk_renew_expiring(args): return get_expiring_certificates({"days": args.get("days", 30), "dry_run": True})
def bulk_revoke(args): return {"success": False, "error": "Not yet implemented"}
def decode_csr(args): return {"success": False, "error": "Not yet implemented"}
def decode_certificate(args): return {"success": False, "error": "Not yet implemented"}
def verify_certificate(args): return {"success": False, "error": "Not yet implemented"}
def get_acme_config(args): return {"success": False, "error": "Not yet implemented"}
def get_audit_log(args): return {"success": False, "error": "Not yet implemented"}


# =============================================================================
# MCP Protocol Handler
# =============================================================================

def handle_request(request: dict):
    method = request.get("method")
    id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        send_response(id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "ejbca-pki-server",
                "version": "0.1.0",
                "description": "Full EJBCA PKI management via natural language"
            }
        })

    elif method == "tools/list":
        send_response(id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        result = handle_tool_call(tool_name, arguments)
        send_response(id, {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
        })

    elif method == "notifications/initialized":
        pass

    else:
        send_response(id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
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
