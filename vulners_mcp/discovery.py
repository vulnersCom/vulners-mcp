# vulners_mcp/discovery.py
"""Agent-discovery documents served on the MCP subdomain (mcp.vulners.com).

These give AI agents and crawlers a machine-readable description of the Vulners
MCP server: an ``llms.txt`` guide, a ``robots.txt`` policy, an SEP-1649 MCP
server card, and an RFC 9727 API catalog.  The content is kept here as module
constants / builders so ``server.py`` stays small and the documents need no
filesystem access at request time.
"""

from __future__ import annotations

from typing import Any, Dict

# Public URLs referenced by the discovery documents.
MCP_ENDPOINT = "https://mcp.vulners.com/mcp"
HEALTH_URL = "https://mcp.vulners.com/health"
LLMS_TXT_URL = "https://mcp.vulners.com/llms.txt"
WEBSITE_URL = "https://vulners.com"
REPOSITORY_URL = "https://github.com/vulnersCom/vulners-mcp"
OPENAPI_URL = "https://vulners.com/api/openapi.json"
API_DOCS_URL = "https://docs.vulners.com/docs/api/"

# Fallback protocol revision if the installed MCP SDK does not expose one.
_FALLBACK_PROTOCOL_VERSION = "2025-06-18"


# -------------------- llms.txt --------------------
LLMS_TXT = """\
# Vulners MCP

> Vulners MCP is a Model Context Protocol (MCP) server over the Vulners vulnerability API. It gives AI agents and assistants real-time CVE, advisory, exploit, and software / Linux-package audit data from the Vulners corpus, beyond the model training cutoff.

## Endpoint

- MCP endpoint: https://mcp.vulners.com/mcp (Streamable HTTP transport)

## Authentication

Send your Vulners API key in the `X-Api-Key` HTTP request header on every request; the server forwards the header to the Vulners API per request. Obtain a free API key at https://vulners.com/userinfo.

## Tools

- bulletin_by_id: Fetch a full vulnerability bulletin by CVE or Vulners ID (single ID or a list of IDs).
- search_lucene: Full-text discovery search of the Vulners knowledge base using Lucene syntax.
- audit_software: Audit specific software versions (structured CPE) for known vulnerabilities.
- get_supported_os: List the OS identifiers/versions supported by the Linux package audit.
- audit_linux_packages: Audit Linux packages (RPM/DEB) for a given distribution and version.
- query_autocomplete: Autocomplete suggestions for vendors, products, and CVEs.
- search_cpe: Find CPE strings by vendor and product.

## Links

- Vulners llms.txt: https://vulners.com/llms.txt
- Authentication (auth.md): https://vulners.com/auth.md
- API documentation: https://docs.vulners.com/docs/api/
- Source code: https://github.com/vulnersCom/vulners-mcp
"""


# -------------------- robots.txt --------------------
ROBOTS_TXT = "User-agent: *\nAllow: /\n# See https://mcp.vulners.com/llms.txt\n"


def _latest_protocol_version() -> str:
    """Return the highest MCP protocol revision the installed SDK supports."""
    try:
        from mcp.types import LATEST_PROTOCOL_VERSION

        return str(LATEST_PROTOCOL_VERSION)
    except Exception:  # pragma: no cover - defensive fallback
        return _FALLBACK_PROTOCOL_VERSION


# -------------------- SEP-1649 MCP server card --------------------
def build_server_card(version: str) -> Dict[str, Any]:
    """Build the ``/.well-known/mcp/server-card.json`` payload.

    ``version`` is read from the running FastMCP instance so the card always
    matches the ``serverInfo.version`` returned by the ``initialize`` handshake.
    """
    return {
        "serverInfo": {
            "name": "Vulners MCP",
            "version": version,
            "title": "Vulners Vulnerability Intelligence",
            "description": (
                "Live, structured vulnerability intelligence (CVEs, advisories, "
                "exploits) and software / Linux-package audits from the Vulners "
                "corpus, exposed to AI agents over the Model Context Protocol."
            ),
            "websiteUrl": WEBSITE_URL,
            "repository": REPOSITORY_URL,
        },
        "protocolVersion": _latest_protocol_version(),
        "transport": {
            "type": "streamable-http",
            "endpoint": MCP_ENDPOINT,
        },
        "capabilities": {
            "tools": {"listChanged": True},
            "resources": {"subscribe": False, "listChanged": True},
            "prompts": {"listChanged": True},
        },
    }


# -------------------- RFC 9727 API catalog --------------------
def build_api_catalog() -> Dict[str, Any]:
    """Build the ``/.well-known/api-catalog`` linkset (RFC 9727)."""
    return {
        "linkset": [
            {
                "anchor": MCP_ENDPOINT,
                "service-desc": [
                    {
                        "href": OPENAPI_URL,
                        "type": "application/json",
                        "title": "Vulners API OpenAPI description",
                    }
                ],
                "service-doc": [
                    {
                        "href": API_DOCS_URL,
                        "type": "text/html",
                        "title": "Vulners API reference",
                    }
                ],
                "status": [
                    {
                        "href": HEALTH_URL,
                        "type": "text/plain",
                        "title": "Vulners MCP health",
                    }
                ],
            }
        ]
    }
