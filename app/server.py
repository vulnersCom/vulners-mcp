# app/server.py
from __future__ import annotations
from typing import Any, Dict, Optional
import asyncio

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

from .settings import settings
from .vulners_client import VulnersClient
from .models import (
    LuceneSearchResponse, AutocompleteResponse, CpeSearchResponse,
    LinuxPackageAuditResponse, WindowsAuditBulletin, ErrorResponse
)


# -------------------- FastMCP server config --------------------
mcp = FastMCP("Vulners MCP")
# Bind networking for the built-in Streamable HTTP server:
mcp.settings.host = settings.host            # e.g. "0.0.0.0"
mcp.settings.port = settings.port            # e.g. 8000
# Many builds default to "/mcp/"; keep it explicit if your FastMCP exposes this setting:
try:
    mcp.settings.streamable_http_path = settings.streamable_http_path  # e.g. "/mcp/"
except Exception:
    pass


# -------------------- Per-request auth header forwarding --------------------
# Only forward auth-related headers; avoid hop-by-hop headers, etc.
_FORWARDABLE = {"x-api-key", "authorization"}

def _forward_headers() -> Dict[str, str] | None:
    """
    Extract forwardable auth headers from the current MCP HTTP request.
    Returns a dict like {"X-Api-Key": "..."} or {"Authorization": "Bearer ..."}.
    If no relevant header is present, returns None (the VulnersClient will fall back to env key).
    """
    raw = get_http_headers(include_all=True) or {}
    lower = {str(k).lower(): str(v) for k, v in raw.items()}

    out: Dict[str, str] = {}
    if "x-api-key" in lower and lower["x-api-key"]:
        out["X-Api-Key"] = lower["x-api-key"].strip()
    if "authorization" in lower and lower["authorization"]:
        out["Authorization"] = lower["authorization"].strip()
    return out or None


# -------------------- Lazy, shared Vulners HTTP client --------------------
_client: VulnersClient | None = None
_client_lock = asyncio.Lock()

async def _get_client() -> VulnersClient:
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is None:
            c = VulnersClient()  # uses settings.vulners_base_url and env default key
            await c.start()
            _client = c
    return _client


# -------------------- Tools (no ctx param; headers auto-forwarded) --------------------
@mcp.tool()
async def search_lucene(body: Dict[str, Any]) -> LuceneSearchResponse:
    """Full-text search in Vulners Knowledge Base.
    Advanced vulnerability search tool using Lucene syntax to query a comprehensive database of over 4 million vulnerability bulletins from various sources.

    This tool provides powerful search capabilities with Boolean operators (AND, OR, NOT), field-specific queries, range searches, and wildcard matching. It includes detailed descriptions of specific vulnerabilities, their unique identifiers (CVE IDs), CVSS scores, affected software, and relevant metadata.

    **Lucene Query Syntax Examples:**

    Basic searches:
    - Simple CVE lookup: "CVE-2020-1232"
    - Software vulnerabilities: affectedSoftware.name:"*Chrome*" OR affectedPackage.packageName:"*Chrome*"
    - Version-specific: affectedSoftware.name:nginx AND affectedSoftware.version:1.1*
    - Package vulnerabilities: affectedPackage.packageName:libcurl*

    Boolean operations:
    - Combined conditions: "apache" AND "vulnerabilities"
    - Multiple options: "apache" OR "nginx"
    - Exclusions: title:php* -type:openvas -type:nessus

    Advanced filtering:
    - CVSS score ranges: cvss3.cvssV3.baseScore:[8 TO 10]
    - Date ranges: published:[2024-01-01 TO 2024-04-01] type:cve
    - Bulletin families: bulletinFamily:exploit
    - Exploited vulnerabilities: enchantments.exploitation.wildExploited:*

    Sorting and ordering:
    - By CVSS score: order:cvss3.cvssV3.baseScore
    - By publication date: order:published
    - By bounty amount: order:bounty

    **Available Fields:**
    - id, title, description, short_description
    - type, bulletinFamily, cvss, published, modified
    - affectedSoftware, affectedPackage, cvelist
    - enchantments (AI scores, exploitation status)

    **Use Cases:**
    - Research specific CVEs: "Tell me about CVE-2020-1232"
    - Find software vulnerabilities: "What vulnerabilities exist in Apache Log4j?"
    - High-severity issues: "Show me critical vulnerabilities with CVSS > 9"
    - Recent threats: "Find vulnerabilities published in the last month"
    - Exploited vulnerabilities: "Show me actively exploited CVEs"

    Endpoint:
      POST /api/v3/search/lucene

    Auth:
      Send your Vulners API key as a header when connecting to the MCP server:
        X-Api-Key: <key>
      (This server forwards the header to Vulners per request.)

    Request body:
      {
        "query": "<lucene query>",
        "skip": 0,                       # optional
        "size": 20,                      # optional (server max applies)
        "fields": ["id","title","cvss"]  # optional
      }

    Example:
      {
        "query": "cve:2024-* AND type:cve",
        "size": 3,
        "fields": ["id","title","cvss","published"]
      }

    Returns:
      JSON with "total", "results" (array of bulletins), and pagination info.
    """
    client = await _get_client()
    result = await client.search_lucene(body, headers=_forward_headers())
    # TODO: fix model to match actual response structure
    return result

@mcp.tool()
async def search_by_id(body: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch full bulletin(s) by CVE or Vulners ID.
    Retrieve complete detailed information for a specific vulnerability bulletin using its unique identifier.

    This tool fetches comprehensive data for a single vulnerability bulletin, providing all available fields and metadata. It's ideal for getting in-depth information about a specific vulnerability when you already know its identifier.

    **What you get:**
    - **Complete vulnerability details**: Full description, technical details, and impact assessment
    - **CVSS scoring**: Both CVSSv2 and CVSSv3 metrics with detailed breakdown
    - **Affected systems**: Comprehensive list of affected software, versions, and packages
    - **Timeline information**: Publication date, modification history, and discovery details
    - **Reference links**: Official advisories, patches, and additional resources
    - **Exploitation data**: Information about known exploits, proof-of-concepts, and wild exploitation
    - **AI-enhanced metadata**: Vulners' AI scoring and additional context
    - **Related bulletins**: Connected CVEs, advisories, and security notices

    **Supported ID formats:**
    - CVE identifiers: "CVE-2024-21762", "CVE-2023-12345"
    - Vendor-specific IDs: "RHSA-2024:1234", "DSA-2024-567"
    - Vulners internal IDs: "VULNERS:2024-12345"
    - Security advisory IDs: "MS24-001", "CISCO-SA-20240101"

    **Use cases:**
    - Get complete details for a known CVE: "Show me full details for CVE-2024-21762"
    - Analyze specific vulnerability impact: "What's the complete technical breakdown of this CVE?"
    - Research exploitation status: "Has this vulnerability been exploited in the wild?"
    - Check for available patches: "What fixes are available for this security issue?"
    - Validate vulnerability details: "Confirm the CVSS score and affected versions"
    - Investigate related threats: "What other vulnerabilities are connected to this one?"

    **Returned data includes:**
    - Basic information: ID, title, description, type, bulletin family
    - Scoring: CVSS v2/v3 base scores, temporal scores, environmental scores
    - Affected systems: Software names, version ranges, package details
    - Dates: Published, modified, discovered timestamps
    - References: URLs to patches, advisories, vendor statements
    - Exploitation: Known exploits, PoCs, wild exploitation status
    - AI analysis: Vulners AI score, risk assessment, contextual information

    This tool complements the search_lucene tool - use search_lucene to find vulnerabilities, then use get_bulletin to get complete details for specific items of interest.
    Endpoint:
      POST /api/v3/search/id

    Auth:
      X-Api-Key: <key>

    Request body:
      {
        "id": "CVE-2024-3094" | ["CVE-2024-3094", "VCID-…"],
        "fields": ["id","title","cvss"],      # optional
        "references": true                    # optional
      }

    Example:
      { "id": ["CVE-2024-3094"], "fields": ["id","title","cvss","published"] }

    Returns:
      JSON bulletin object (single id) or id→bulletin mapping (multiple ids).
    """
    client = await _get_client()
    return await client.search_by_id(body, headers=_forward_headers())

@mcp.tool()
async def audit_software(body: Dict[str, Any]) -> Dict[str, Any]:
    """Audit a list of software/CPEs for known vulnerabilities.

    Endpoint:
      POST /api/v4/audit/software

    Auth:
      X-Api-Key: <key>

    Request body:
      {
        "software": [ "<cpe-string>" | {CPE object}, ... ],
        "match": "partial" | "full",       # optional, default "partial"
        "fields": ["id","title","cvss"]    # optional
      }
      • software: Each item can be a full CPE string (e.g. "cpe:/a:openssl:openssl:1.1.1u")
        or a structured CPE object with keys like vendor, product, version, target_sw, etc.
      • match: "partial" matches a wider set (recommended); "full" requires exact match.

    Example:
      {
        "software": [
          "cpe:/a:openssl:openssl:1.1.1u",
          "cpe:/a:apache:http_server:2.4.58"
        ],
        "match": "partial",
        "fields": ["id","title","cvss","published"]
      }

    Returns:
      JSON with an entry per input item, including matched criteria and a
      "vulnerabilities" array per item.
    """
    client = await _get_client()
    return await client.audit_software(body, headers=_forward_headers())

@mcp.tool()
async def audit_host(body: Dict[str, Any]) -> Dict[str, Any]:
    """Context-aware host audit (OS + software) for known vulnerabilities.

    Endpoint:
      POST /api/v4/audit/host

    Auth:
      X-Api-Key: <key>

    Request body (typical):
      {
        "os": "windows" | "linux" | "macos" | "<identifier>",
        "os_version": "22H2" | "22.04" | "<version>",
        "software": [ "<cpe-string>" | {CPE object}, ... ],
        "kbList": ["KB5003791", ...],          # optional (Windows)
        "fields": ["id","title","cvss"]        # optional
      }

    Example:
      {
        "os": "windows",
        "os_version": "10",
        "kbList": ["KB5039211"],
        "software": ["cpe:/a:google:chrome:126.0.6478.126"],
        "fields": ["id","title","cvss","vulners_score"]
      }

    Returns:
      JSON describing matched vulnerabilities given the host context.
    """
    client = await _get_client()
    return await client.audit_host(body, headers=_forward_headers())

@mcp.tool()
async def audit_windows_kb(body: Dict[str, Any]) -> Dict[str, Any]:
    """Audit a Windows system by installed KBs (patches).

    Endpoint:
      POST /api/v3/audit/kb

    Auth:
      X-Api-Key: <key>

    Request body:
      {
        "os": "microsoft_windows_10" | "microsoft_windows_server_2019" | ...,
        "kbList": ["KB5039211","KB5039217", ...]
      }

    Example:
      { "os": "microsoft_windows_10", "kbList": ["KB5039211","KB5039217"] }

    Returns:
      JSON with missing/required updates and related vulnerabilities for the given KB state.
    """
    client = await _get_client()
    return await client.audit_windows_kb(body, headers=_forward_headers())

@mcp.tool()
async def audit_windows(body: Dict[str, Any]) -> Dict[str, Any]:
    """Windows audit with OS build + installed KBs + optional software list.

    Endpoint:
      POST /api/v3/audit/winaudit

    Auth:
      X-Api-Key: <key>

    Request body:
      {
        "os": "microsoft_windows_10" | "microsoft_windows_server_2019" | ...,
        "os_version": "<build or version>",
        "kbList": ["KB5039211","KB5039217", ...],
        "software": [
          {"software": "cpe:/a:google:chrome", "version": "126.0.6478.126"},
          ...
        ]
      }

    Example:
      {
        "os": "microsoft_windows_10",
        "os_version": "22H2",
        "kbList": ["KB5039211"],
        "software": [{"software":"cpe:/a:adobe:acrobat_reader:23.008.20533"}]
      }

    Returns:
      JSON with patch/vulnerability findings derived from OS build, KBs, and app list.
    """
    client = await _get_client()
    return await client.audit_windows(body, headers=_forward_headers())

@mcp.tool()
async def audit_linux_packages(body: Dict[str, Any]) -> LinuxPackageAuditResponse:
    """Linux package audit (RPM/DEB) for a given distro + version.

    Endpoint:
      POST /api/v3/audit/audit

    Auth:
      X-Api-Key: <key>

    Request body:
      {
        "os": "<distro-id>",                 # e.g. "ubuntu", "debian", "centos", "rhel"
        "version": "<release>",              # e.g. "22.04", "12", "8"
        "package": ["pkg-ver" | "name-ver-rel", ...],
        "include_candidates": false          # optional; include potential matches
      }

    Example:
      {
        "os": "ubuntu",
        "version": "22.04",
        "package": ["openssl-3.0.2", "curl-7.81.0-1ubuntu1.14"],
        "include_candidates": false
      }

    Returns:
      JSON describing vulnerable packages, fixed versions (if available),
      and linked advisories. Use get_supported_os() to discover valid OS ids.
    """
    client = await _get_client()
    result = await client.audit_linux_packages(body, headers=_forward_headers())
    # TODO: fix model to match actual response structure
    return result

@mcp.tool()
async def get_supported_os() -> Dict[str, Any]:
    """List supported OS identifiers/versions for Linux package audit.

    Endpoint:
      GET /api/v3/audit/getSupportedOS

    Auth:
      X-Api-Key: <key> (recommended)

    Request:
      No parameters.

    Returns:
      JSON list of supported operating systems and versions to use with audit_linux_packages().
    """
    client = await _get_client()
    return await client.get_supported_os(headers=_forward_headers())

@mcp.tool()
async def query_autocomplete(body: Dict[str, Any]) -> AutocompleteResponse:
    """Autocomplete helper for search inputs (vendors, products, CVEs, etc.).

    Endpoint:
      POST /api/v3/search/autocomplete

    Auth:
      X-Api-Key: <key>

    Request body:
      { "query": "<partial query>" }

    Examples:
      { "query": "openssl" }
      { "query": "CVE-2024-" }
      { "query": "microsoft windows" }

    Returns:
      JSON suggestions that can be fed into search_lucene() or search_cpe().
    """
    client = await _get_client()
    result = await client.query_autocomplete(body, headers=_forward_headers())
    # TODO: fix model to match actual response structure
    return result

@mcp.tool()
async def search_cpe(vendor: str, product: str, size: int | None = None) -> CpeSearchResponse:
    """Find CPE strings by vendor+product (latest schema).

    Endpoint:
      GET /api/v4/search/cpe

    Auth:
      X-Api-Key: <key>

    Query params:
      vendor:  e.g. "microsoft"
      product: e.g. "windows_10"
      size:    optional limit (server default applies)

    Example:
      vendor="microsoft", product="windows_10", size=5

    Returns:
      JSON with "best_match" and a "cpe" array of candidate CPE strings.
    """
    client = await _get_client()
    result = await client.search_cpe(vendor=vendor, product=product, size=size, headers=_forward_headers())
    # TODO: fix model to match actual response structure
    return result

@mcp.tool()
async def fetch_collection(type: str) -> Dict[str, Any]:
    """Fetch records from a named archive collection.

    Endpoint:
      GET /api/v4/archive/collection

    Auth:
      X-Api-Key: <key>

    Query params:
      type: Name of the collection to retrieve (e.g., "cve", "oval", "ms-kb", etc.)

    Example:
      type="cve"

    Returns:
      JSON array of records in the requested collection (schema varies by collection).
    """
    client = await _get_client()
    return await client.fetch_collection(type, headers=_forward_headers())

@mcp.tool()
async def fetch_collection_update(type: str, after_iso: str) -> Dict[str, Any]:
    """Incremental collection sync: items updated after a given timestamp.

    Endpoint:
      GET /api/v4/archive/collection-update

    Auth:
      X-Api-Key: <key>

    Query params:
      type:     Collection name (e.g., "cve")
      after:    ISO-8601 timestamp (UTC), e.g. "2024-07-01T00:00:00Z"

    Example:
      type="cve", after_iso="2024-07-01T00:00:00Z"

    Returns:
      JSON array of collection entries updated strictly after the provided timestamp.
    """
    client = await _get_client()
    return await client.fetch_collection_update(type, after_iso, headers=_forward_headers())

@mcp.tool()
async def get_os_cve_archive(os: str, version: str) -> str:
    """Download a ZIP archive of CVE data for a specific OS + version.

    Endpoint:
      GET /api/v3/archive/distributive

    Auth:
      X-Api-Key: <key>

    Params:
      os:      OS identifier (e.g., "ubuntu", "debian", "centos")
      version: OS release (e.g., "22.04", "12")

    Behavior in this MCP server:
      The endpoint returns ZIP bytes; the server writes them to a secure temp file
      and returns the absolute path to that file for the client to consume.

    Example:
      os="ubuntu", version="22.04"  → "/tmp/ubuntu-22.04-XXXX.zip"

    Returns:
      Absolute file path (string) to the downloaded ZIP on the server.
    """
    client = await _get_client()
    content = await client.get_os_cve_archive(os=os, version=version, headers=_forward_headers())
    import tempfile, os as _os
    fd, path = tempfile.mkstemp(prefix=f"{os}-{version}-", suffix=".zip")
    with _os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


# -------------------- Optional MCP resource (not HTTP) --------------------
@mcp.resource("health://ready")
def health_ready() -> str:
    return "ok"


# -------------------- Run built-in Streamable HTTP server --------------------
if __name__ == "__main__":
    # Clients (e.g., MCP Inspector) must connect to: http://<host>:<port>/mcp/
    mcp.run(transport="streamable-http")
