# vulners_mcp/discovery.py
"""Agent-discovery documents served on the MCP subdomain (mcp.vulners.com).

These give AI agents and crawlers a machine-readable description of the Vulners
MCP server: an ``llms.txt`` guide, an ``auth.md`` authentication policy, a
``robots.txt`` policy, an SEP-1649 MCP server card, an RFC 9727 API catalog,
and a DNS-AID organization agent index. The content is kept here as module
constants / builders so ``server.py`` stays small and the documents need no
filesystem access at request time.
"""

from __future__ import annotations

from typing import Any, Dict

from .settings import settings

# Public URLs referenced by the discovery documents.
MCP_ENDPOINT = "https://mcp.vulners.com/mcp"
HEALTH_URL = "https://mcp.vulners.com/health"
LLMS_TXT_URL = "https://mcp.vulners.com/llms.txt"
AUTH_MD_URL = "https://mcp.vulners.com/auth.md"
MCP_SERVER_CARD_URL = "https://mcp.vulners.com/.well-known/mcp/server-card.json"
AGENTS_INDEX_URL = "https://mcp.vulners.com/.well-known/agents/index.json"
WEBSITE_URL = "https://vulners.com"
REPOSITORY_URL = "https://github.com/vulnersCom/vulners-mcp"
OPENAPI_URL = "https://vulners.com/api/openapi.json"
API_DOCS_URL = "https://docs.vulners.com/docs/api/"
VULNERS_USERINFO_URL = "https://vulners.com/userinfo"
VULNERS_AUTH_MD_URL = "https://vulners.com/auth.md"
VULNERS_LLMS_TXT_URL = "https://vulners.com/llms.txt"

# Fallback protocol revision if the installed MCP SDK does not expose one.
_FALLBACK_PROTOCOL_VERSION = "2025-06-18"


# -------------------- llms.txt --------------------
# An f-string, deliberately: every URL below is interpolated from the same
# constants ``build_server_card``/``build_agents_index`` use, so this
# document cannot silently drift from what the server actually serves (see
# tests/test_discovery_routes.py for the tool-name drift guard on top).
LLMS_TXT = f"""\
# Vulners MCP

> Vulners MCP is a Model Context Protocol (MCP) server over the Vulners vulnerability API. It gives AI agents and assistants real-time CVE, advisory, exploit, and software / Linux-package audit data from the Vulners corpus, beyond the model training cutoff.

## Endpoint

- MCP endpoint: {MCP_ENDPOINT} (Streamable HTTP transport)

## Authentication

This server holds no privileged API key of its own. Send your personal Vulners API key in the `X-Api-Key` HTTP request header for full, uncapped limits; the server forwards it to the Vulners API per request and never stores or issues one on your behalf. Omit the header entirely and the call still goes through, on this deployment's own dedicated, low-privilege anonymous-tier key (when configured) -- reduced limits: result-size arguments clamped to {settings.anon_max_size}, plus a shared, modest rate limit. `initialize` and `tools/list` always work without a key either way. Humans get a key by signing in at {VULNERS_USERINFO_URL} in a browser -- an agent fetching that URL directly gets an interactive challenge instead, by design. Full policy: {AUTH_MD_URL}.

## Tools

- bulletin_by_id: Fetch a vulnerability bulletin by CVE or Vulners ID (single ID or a list of IDs). Returns a COMPACT summary by default (id, title, CVSS3, EPSS, exploitation signal, CVE list); pass `fields=[...]` (e.g. `"description"`) or `references=True` to widen -- requesting everything can be very large.
- search_lucene: Full-text discovery search of the Vulners knowledge base using Lucene syntax.
- audit_software: Audit specific software versions (structured CPE) for known vulnerabilities.
- get_supported_os: List the OS identifiers/versions supported by the Linux package audit.
- audit_linux_packages: Audit Linux packages (RPM/DEB) for a given distribution and version.
- query_autocomplete: Autocomplete suggestions for vendors, products, and CVEs.
- search_cpe: Find CPE strings by vendor and product.

## Links

- Vulners llms.txt: {VULNERS_LLMS_TXT_URL}
- Authentication (this server): {AUTH_MD_URL}
- Authentication (full registration walk-through): {VULNERS_AUTH_MD_URL}
- MCP server card: {MCP_SERVER_CARD_URL}
- Organization agent index: {AGENTS_INDEX_URL}
- API documentation: {API_DOCS_URL}
- Source code: {REPOSITORY_URL}
"""


# -------------------- auth.md --------------------
AUTH_MD = f"""\
# auth.md

Authentication policy for the Vulners MCP server (mcp.vulners.com), written for AI agents and other automated clients.

## This server holds no privileged API key of its own

This server never has a privileged Vulners API key of its own to spend on your behalf, and it never issues, stores, or shares your key. A caller-supplied key that Vulners itself rejects (expired, revoked, wrong scope) is never silently retried on any other key -- you get a sanitized error back, not a masked failure.

## Two ways to call it

- **Bring your own key (full limits).** Send your personal Vulners API key in the `X-Api-Key` HTTP request header on MCP tool calls (`tools/call`). It is forwarded to the Vulners API for that request only: full limits, no result-size clamp, no app-level rate limit.
- **Anonymous tier (reduced limits).** Omit the `X-Api-Key` header entirely and the call still goes through, on this deployment's own dedicated, low-privilege key -- when one is configured. Result-size arguments are clamped to {settings.anon_max_size}, and anonymous calls share a modest, app-level rate limit protecting that shared key's quota. If the anonymous-tier key's own quota or rate limit is exhausted upstream, you get a structured error telling you to send your own key for full limits. If this deployment has no anonymous tier configured at all, a keyless call fails immediately with a guidance error instead of being forwarded.
- **Discovery is always open**: `initialize` and `tools/list` work without a key either way, so an agent can inspect what this server offers before deciding whether it needs its own key.

## Getting or rotating a key (humans only)

Sign in at {VULNERS_USERINFO_URL} in a regular web browser to create, view, or rotate your API key. That page is protected by an interactive challenge -- an agent or automated client fetching it directly gets a challenge page back instead of a key, by design. A human has to complete this step.

Key scopes (`api`, `scan`, `report`) and IP allowlists are also configured there.

## Self-hosted / stdio mode

Running this server yourself over stdio (e.g. from Claude Desktop)? Set the `VULNERS_API_KEY` environment variable to your own key. In stdio mode the server uses it for every tool call, since there is no per-request HTTP header available -- the anonymous tier is an HTTP-transport concept only and does not apply here.

## Full registration walk-through

For the complete, non-agent-specific walkthrough of Vulners account creation and key management, see {VULNERS_AUTH_MD_URL}.

## Machine-readable descriptors

- MCP server card: {MCP_SERVER_CARD_URL}
"""


# -------------------- robots.txt --------------------
ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Allow: /llms.txt\n"
    "Allow: /auth.md\n"
    "Allow: /.well-known/\n"
    "# See https://mcp.vulners.com/llms.txt\n"
)


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
    ``protocolVersion`` likewise comes from the installed SDK's own constant
    (``_latest_protocol_version``), never a literal, so both fields track
    reality automatically as the server and SDK are upgraded.
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
        # Mirrors the real policy enforced by auth.AuthMiddleware (HTTP
        # tools/call) -- this section is a description of that enforcement,
        # not a separate promise, so it can't drift from what the server
        # actually does. maxResultSize is read live from
        # settings.anon_max_size, not a literal. ``required`` is likewise
        # derived from ``settings.anon_api_key`` -- the SAME truthiness
        # check ``auth.resolve_effective_auth`` uses to decide between its
        # "anon-tier" and "none" modes (see auth.py) -- rather than a
        # separate literal that could silently drift from what a keyless
        # `tools/call` actually does on this deployment.
        "authentication": {
            "anonymousDiscovery": True,
            "toolInvocation": {
                "required": not bool(settings.anon_api_key),
                "anonymousTier": {
                    "allowed": True,
                    "maxResultSize": settings.anon_max_size,
                    "rateLimited": True,
                    "note": (
                        "Anonymous tier requires this deployment to have a "
                        "dedicated anon-tier key configured; if not "
                        "configured (see toolInvocation.required), a "
                        "keyless call fails with a guidance error instead."
                    ),
                },
                "apiKeyHeader": "X-Api-Key",
                "apiKeyBenefit": "full limits: no result-size clamp, no app-level rate limit",
            },
            "authMdUrl": AUTH_MD_URL,
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


# -------------------- DNS-AID organization agent index --------------------
def build_agents_index() -> Dict[str, Any]:
    """Build the ``/.well-known/agents/index.json`` organization agent index.

    This is the artifact a DNS-AID ``_index._agents.vulners.com`` TXT record
    would point at: a small, organization-level directory of every
    agent-reachable protocol this origin exposes. Currently that's just MCP.
    The entry's ``endpoint``/``card`` URLs are built from the same constants
    the individual routes use (``MCP_ENDPOINT``, ``MCP_SERVER_CARD_URL``),
    and a dedicated test cross-checks each one against the app's own route
    table so this can't quietly go stale (see
    ``tests/test_discovery_routes.py``).
    """
    return {
        "version": "1",
        "organization": {
            "name": "Vulners",
            "domain": "vulners.com",
            "url": WEBSITE_URL,
        },
        "agents": [
            {
                "name": "Vulners MCP",
                "protocol": "mcp",
                "endpoint": MCP_ENDPOINT,
                "card": MCP_SERVER_CARD_URL,
                "dns": "_mcp._agents.vulners.com",
            },
        ],
    }
