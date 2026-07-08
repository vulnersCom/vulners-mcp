"""Tests for the agent-discovery HTTP routes served on the MCP subdomain.

They exercise the ASGI app returned by ``FastMCP.http_app()`` (which carries the
``@mcp.custom_route`` handlers) with Starlette's ``TestClient`` and assert that
each new route returns 200, the right content type, and key content markers.

A few tests below need more than ``mcp.http_app()`` alone: the agent index
(``/.well-known/agents/index.json``) lists A2A endpoints that only exist on
the fully composed ASGI app (MCP + A2A, see ``vulners_mcp.asgi``), not on the
bare MCP app. Those build a fresh composed app locally, following the same
pattern as ``tests/test_asgi_composition.py``.
"""

from __future__ import annotations

import json
import re

import pytest
from mcp.types import LATEST_PROTOCOL_VERSION
from starlette.testclient import TestClient

from vulners_mcp import discovery
from vulners_mcp.a2a_app import build_a2a_routes
from vulners_mcp.asgi import build_asgi_app
from vulners_mcp.server import mcp
from vulners_mcp.settings import settings


@pytest.fixture(scope="module")
def client() -> TestClient:
    # The context manager runs the FastMCP lifespan (session manager, etc.).
    with TestClient(mcp.http_app()) as test_client:
        yield test_client


def test_llms_txt(client: TestClient) -> None:
    resp = client.get("/llms.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "# Vulners MCP" in body
    assert "https://mcp.vulners.com/mcp" in body
    assert "X-Api-Key" in body
    # All seven tools must be listed.
    for tool in (
        "bulletin_by_id",
        "search_lucene",
        "audit_software",
        "get_supported_os",
        "audit_linux_packages",
        "query_autocomplete",
        "search_cpe",
    ):
        assert tool in body


def test_llms_txt_authentication_is_honest(client: TestClient) -> None:
    """No more "Obtain a free API key at .../userinfo" -- this server does
    not hand out keys, humans get their own at vulners.com, and the policy
    is spelled out in full at /auth.md."""
    body = client.get("/llms.txt").text
    assert "This server holds no API keys of its own" in body
    assert "https://vulners.com/userinfo" in body
    assert "https://mcp.vulners.com/auth.md" in body
    # The old, misleading phrasing must be gone.
    assert "Obtain a free API key" not in body


def test_llms_txt_has_a2a_section(client: TestClient) -> None:
    """A2A is real now (shipped in the same release) -- llms.txt must say so."""
    body = client.get("/llms.txt").text
    assert "## A2A" in body
    assert "https://mcp.vulners.com/a2a" in body
    assert "https://mcp.vulners.com/.well-known/agent-card.json" in body


async def test_llms_txt_tool_names_match_registered_tools(client: TestClient) -> None:
    """Drift guard: the tool list in llms.txt must exactly match the tools
    actually registered on the running server -- not a hand-maintained copy
    that can silently fall out of sync when a tool is added, renamed, or
    removed."""
    body = client.get("/llms.txt").text
    tools_section = body.split("## Tools", 1)[1].split("## A2A", 1)[0]
    listed_tools = set(re.findall(r"^- (\w+):", tools_section, flags=re.MULTILINE))

    live_tools = set((await mcp.get_tools()).keys())

    assert listed_tools == live_tools
    assert len(listed_tools) == 7


def test_auth_md(client: TestClient) -> None:
    resp = client.get("/auth.md")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    body = resp.text
    assert body.startswith("# auth.md")
    assert "holds no API keys" in body
    assert "X-Api-Key" in body
    assert "https://vulners.com/userinfo" in body
    assert "interactive challenge" in body
    assert "VULNERS_API_KEY" in body
    assert "https://vulners.com/auth.md" in body
    assert "https://mcp.vulners.com/.well-known/mcp/server-card.json" in body
    assert "https://mcp.vulners.com/.well-known/agent-card.json" in body


def test_robots_txt(client: TestClient) -> None:
    resp = client.get("/robots.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in resp.text
    assert "Allow: /" in resp.text
    assert "https://mcp.vulners.com/llms.txt" in resp.text


def test_robots_txt_allows_the_well_known_discovery_paths(client: TestClient) -> None:
    body = client.get("/robots.txt").text
    assert "Allow: /llms.txt" in body
    assert "Allow: /auth.md" in body
    assert "Allow: /.well-known/" in body
    assert "Disallow" not in body


def test_server_card(client: TestClient) -> None:
    resp = client.get("/.well-known/mcp/server-card.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    data = resp.json()
    assert data["serverInfo"]["name"] == "Vulners MCP"
    # Version is read dynamically from the running server, never hardcoded.
    assert data["serverInfo"]["version"] == mcp.version
    assert data["transport"]["endpoint"] == "https://mcp.vulners.com/mcp"
    assert "protocolVersion" in data


def test_server_card_authentication_block(client: TestClient) -> None:
    data = client.get("/.well-known/mcp/server-card.json").json()
    auth = data["authentication"]
    assert auth["anonymousDiscovery"] is True
    assert auth["toolInvocation"] == {"required": True, "apiKeyHeader": "X-Api-Key"}
    assert auth["authMdUrl"] == "https://mcp.vulners.com/auth.md"


def test_server_card_version_matches_initialize(client: TestClient) -> None:
    """The card's version and protocol must equal the live initialize values."""
    card = client.get("/.well-known/mcp/server-card.json").json()

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": str(LATEST_PROTOCOL_VERSION),
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    }
    resp = client.post(
        "/mcp/",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        content=json.dumps(init_req),
    )
    assert resp.status_code == 200
    # Streamable HTTP replies as an SSE frame; pull the JSON payload out of it.
    payload = None
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            payload = json.loads(line[len("data:"):].strip())
            break
    assert payload is not None, resp.text
    server_info = payload["result"]["serverInfo"]
    assert card["serverInfo"]["version"] == server_info["version"]
    assert card["protocolVersion"] == payload["result"]["protocolVersion"]


def test_api_catalog(client: TestClient) -> None:
    resp = client.get("/.well-known/api-catalog")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/linkset+json")
    data = resp.json()
    linkset = data["linkset"][0]
    assert linkset["anchor"] == "https://mcp.vulners.com/mcp"
    assert linkset["service-desc"][0]["href"] == "https://vulners.com/api/openapi.json"
    assert linkset["service-doc"][0]["href"] == "https://docs.vulners.com/docs/api/"
    assert linkset["status"][0]["href"] == "https://mcp.vulners.com/health"


def test_agents_index_json(client: TestClient) -> None:
    resp = client.get("/.well-known/agents/index.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    data = resp.json()
    assert data["version"] == "1"
    assert data["organization"] == {
        "name": "Vulners",
        "domain": "vulners.com",
        "url": "https://vulners.com",
    }
    assert {agent["protocol"] for agent in data["agents"]} == {"mcp", "a2a"}
    for agent in data["agents"]:
        assert agent["endpoint"].startswith("https://mcp.vulners.com/")
        assert agent["card"].startswith("https://mcp.vulners.com/")
        assert agent["dns"].endswith("._agents.vulners.com")


def _all_route_paths(app: object) -> set[str]:
    """Recursively collect every concrete route path on a Starlette app,
    descending into mounted sub-apps (e.g. the MCP app mounted at "/" inside
    the composed ASGI app -- see ``vulners_mcp.asgi.build_asgi_app``)."""
    paths: set[str] = set()
    for route in getattr(app, "routes", []):
        path = getattr(route, "path", None)
        if path:
            paths.add(path)
        sub_app = getattr(route, "app", None)
        if sub_app is not None:
            paths |= _all_route_paths(sub_app)
    return paths


def test_agents_index_urls_are_real_routes_on_the_composed_app() -> None:
    """Self-consistency guard: every endpoint/card URL the agent index lists
    must resolve to an actual route on the fully composed ASGI app (MCP +
    A2A) -- not just a plausible-looking string. Uses a fresh ``mcp_app`` +
    ``build_asgi_app(target_app=...)`` rather than the module-level
    singleton, per the "run once" lifespan constraint documented in
    ``tests/test_asgi_composition.py``.
    """
    fresh_mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    composed = build_asgi_app(extra_routes=build_a2a_routes(), target_app=fresh_mcp_app)
    known_paths = _all_route_paths(composed)

    data = discovery.build_agents_index()
    assert data["agents"], "agent index must not be empty"
    for agent in data["agents"]:
        for field in ("endpoint", "card"):
            url = agent[field]
            path = url.removeprefix("https://mcp.vulners.com")
            assert path in known_paths, (
                f"{agent['name']} {field} {url!r} (path {path!r}) is not a "
                f"route on the composed app; known paths: {sorted(known_paths)}"
            )
