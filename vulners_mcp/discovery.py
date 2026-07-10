# vulners_mcp/discovery.py
"""Agent-discovery documents served on the MCP subdomain (mcp.vulners.com).

These give AI agents and crawlers a machine-readable description of the Vulners
MCP server: an ``llms.txt`` guide, an ``auth.md`` authentication policy, a
``robots.txt`` policy, a ``sitemap.xml``, an SEP-1649 MCP server card, an
RFC 9727 API catalog, a DNS-AID organization agent index, and an Agent Skills
0.2.0 index. The content is kept here as module constants / builders so
``server.py`` stays small and the documents need no filesystem access at
request time.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from .settings import settings

# Public URLs referenced by the discovery documents.
ROOT_URL = "https://mcp.vulners.com/"
MCP_ENDPOINT = "https://mcp.vulners.com/mcp"
HEALTH_URL = "https://mcp.vulners.com/health"
LLMS_TXT_URL = "https://mcp.vulners.com/llms.txt"
AUTH_MD_URL = "https://mcp.vulners.com/auth.md"
SITEMAP_XML_URL = "https://mcp.vulners.com/sitemap.xml"
MCP_SERVER_CARD_URL = "https://mcp.vulners.com/.well-known/mcp/server-card.json"
API_CATALOG_URL = "https://mcp.vulners.com/.well-known/api-catalog"
AGENTS_INDEX_URL = "https://mcp.vulners.com/.well-known/agents/index.json"
AGENT_SKILLS_INDEX_URL = "https://mcp.vulners.com/.well-known/agent-skills/index.json"
# The skill document itself is referenced by a site-relative path in the
# index (see build_agent_skills_index()), matching the Agent Skills 0.2.0
# convention; this is the path the route in server.py is registered on.
AGENT_SKILL_MD_PATH = "/.well-known/agent-skills/vulners-mcp/SKILL.md"
WEBSITE_URL = "https://vulners.com"
REPOSITORY_URL = "https://github.com/vulnersCom/vulners-mcp"
OPENAPI_URL = "https://vulners.com/api/openapi.json"
API_DOCS_URL = "https://docs.vulners.com/docs/api/"
VULNERS_SIGNUP_URL = "https://vulners.com/signup"
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

## Registration and credential provisioning

Registration is interactive (human-in-the-loop); there is no unauthenticated provisioning endpoint. An agent cannot self-register -- ask your human operator to complete Step 1 and hand you the key.

### Step 1 -- Register and provision a credential

1. Create a Vulners account: {VULNERS_SIGNUP_URL}
2. Open the API keys section of the personal area: {VULNERS_USERINFO_URL}
3. Generate an API key (credential type: `api_key`). Optional per-key scopes (`api`, `scan`, `report`) and an optional IP allowlist are configured there.

Both URLs return an interactive challenge to non-browser clients -- they must be opened in a regular browser by the human operator.

### Step 2 -- Use the credential

Send the API key in the `X-Api-Key` request header on every MCP `tools/call`; it is forwarded to the Vulners API for that request only.

### Step 3 -- Rotation and revocation

Keys are listed, rotated and revoked at {VULNERS_USERINFO_URL}. If a previously working key starts returning 401/403 it was revoked or its IP allowlist no longer matches -- obtain a new key via Step 1; do not retry with the stale credential.

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
    "Content-Signal: search=yes, ai-input=yes, ai-train=yes\n"
    "# See https://mcp.vulners.com/llms.txt\n"
    f"Sitemap: {SITEMAP_XML_URL}\n"
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
        # settings.anon_max_size, not a literal.
        "authentication": {
            "anonymousDiscovery": True,
            "toolInvocation": {
                "required": False,
                "anonymousTier": {
                    "allowed": True,
                    "maxResultSize": settings.anon_max_size,
                    "rateLimited": True,
                    "note": (
                        "Anonymous tier requires this deployment to have a "
                        "dedicated anon-tier key configured; if not, a "
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


# -------------------- sitemap.xml --------------------
# The canonical set of agent-discovery URLs on this host, listed so crawlers
# and scanners that only follow sitemap.xml (rather than robots.txt or the
# individual documents' cross-links) still find every discovery surface.
# Built from the same URL constants the routes themselves use, so it cannot
# silently drift from what the server actually serves.
_SITEMAP_URLS = (
    ROOT_URL,
    LLMS_TXT_URL,
    AUTH_MD_URL,
    MCP_SERVER_CARD_URL,
    API_CATALOG_URL,
    AGENTS_INDEX_URL,
    AGENT_SKILLS_INDEX_URL,
)


def _build_sitemap_xml(urls: tuple[str, ...]) -> str:
    entries = "\n".join(f"  <url><loc>{url}</loc></url>" for url in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>\n"
    )


SITEMAP_XML = _build_sitemap_xml(_SITEMAP_URLS)


# -------------------- Agent Skills 0.2.0 --------------------
# SKILL_MD is byte-for-byte the file served at
# https://vulners.com/.well-known/agent-skills/vulners-mcp/SKILL.md (its
# sha256 is pinned in tests/test_discovery_routes.py) so the two hosts
# advertise the identical skill. Keep this content in sync with that file if
# it ever changes -- do not edit it here without also updating vulners.com.
SKILL_MD = """\
---
name: vulners-mcp
description: Query Vulners for live, structured vulnerability intelligence (CVEs, advisories, exploits) and run software / Linux-package audits via the Vulners MCP server. Use when an agent needs ground-truth CVE data or to check whether a product/version is affected.
---

# Vulners MCP

Vulners MCP exposes Vulners' continuously-collected vulnerability corpus
(CVE ↔ advisories ↔ patches ↔ exploits) to AI agents over the Model Context
Protocol, so copilots and agents fetch current, structured context on demand.

- Hosted endpoint: https://mcp.vulners.com/mcp
- Open source: https://github.com/vulnersCom/vulners-mcp

## When to use

Call Vulners MCP when you need current, citable facts about vulnerabilities
instead of relying on training data: explaining a CVE, finding advisories or
exploits, or assessing whether a specific product/version is affected.

## Tools

Intelligence:
- `bulletin_by_id` — fetch full bulletin record(s) by ID (CVE or vendor bulletin).
  Params: `id` (string | string[]). Batch multiple IDs in one call.
- `search_lucene` — search the corpus. Params: `query` (string), `skip` (int),
  `size` (int). Expand hits via `bulletin_by_id`.
- `search_cpe` — resolve CPE strings. `query_autocomplete` — type-ahead for
  vendors / products / CVEs.

Assessment:
- `audit_software` — audit an exact software version. Params: `body` (software
  identifiers: CPE or name+version).
- `audit_linux_packages` — audit a distro package list. Params: `os` (string),
  `version` (string), `package` (string[]), `include_candidates?` (bool). Use
  `get_supported_os` for valid distro identifiers.

## Typical flow

1. Discover with `search_lucene` / `search_cpe` / `query_autocomplete`, or start
   from a known ID.
2. Collect CVE IDs and batch them into `bulletin_by_id` for full, normalized
   records with references.
3. For assets, use `audit_software` / `audit_linux_packages`, then enrich
   surfaced CVE IDs via `bulletin_by_id`.

Outputs are deterministic JSON with references (vendor advisories / patches),
exploitation / KEV indicators, and scoring metrics for triage.
"""


def _parse_skill_md_description(skill_md: str) -> str:
    """Extract the ``description:`` field from SKILL_MD's YAML front matter.

    Parsed at build time (rather than duplicated as a separate literal) so
    ``build_agent_skills_index()`` can never drift from what SKILL_MD itself
    says.
    """
    front_matter = skill_md.split("---", 2)[1]
    for line in front_matter.splitlines():
        if line.startswith("description:"):
            return line[len("description:") :].strip()
    raise ValueError("SKILL_MD front matter is missing a 'description' field")


def build_agent_skills_index() -> Dict[str, Any]:
    """Build the ``/.well-known/agent-skills/index.json`` payload.

    Agent Skills discovery 0.2.0 (https://schemas.agentskills.io/discovery/0.2.0/).
    The ``digest`` is computed from ``SKILL_MD`` at build time -- never a
    literal -- so it can never drift from the bytes the SKILL.md route
    actually serves; see the drift-guard test in
    ``tests/test_discovery_routes.py`` that fetches both and compares them.
    """
    return {
        "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
        "skills": [
            {
                "name": "vulners-mcp",
                "type": "skill-md",
                "description": _parse_skill_md_description(SKILL_MD),
                "url": AGENT_SKILL_MD_PATH,
                "digest": f"sha256:{hashlib.sha256(SKILL_MD.encode()).hexdigest()}",
            }
        ],
    }
