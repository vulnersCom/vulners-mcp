"""Tests for the agent-discovery HTTP routes served on the MCP subdomain.

They exercise the ASGI app returned by ``FastMCP.http_app()`` (which carries the
``@mcp.custom_route`` handlers) with Starlette's ``TestClient`` and assert that
each new route returns 200, the right content type, and key content markers.

One test below needs more than ``mcp.http_app()`` alone: the agent index
self-consistency check builds the fully composed ASGI app (see
``vulners_mcp.asgi``) locally, following the same pattern as
``tests/test_asgi_composition.py``.
"""

from __future__ import annotations

import json
import re

import pytest
from mcp.types import LATEST_PROTOCOL_VERSION
from starlette.testclient import TestClient

from vulners_mcp import discovery
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
    assert "This server holds no privileged API key of its own" in body
    assert "https://vulners.com/userinfo" in body
    assert "https://mcp.vulners.com/auth.md" in body
    # The old, misleading phrasing must be gone.
    assert "Obtain a free API key" not in body


def test_llms_txt_describes_the_anonymous_tier(client: TestClient) -> None:
    """VU-1850 anonymous tier: llms.txt must say a keyless call can still
    go through (reduced limits), not just describe the hard no-key gate."""
    body = client.get("/llms.txt").text
    assert "anonymous-tier" in body or "anonymous tier" in body
    assert str(settings.anon_max_size) in body


async def test_llms_txt_tool_names_match_registered_tools(client: TestClient) -> None:
    """Drift guard: the tool list in llms.txt must exactly match the tools
    actually registered on the running server -- not a hand-maintained copy
    that can silently fall out of sync when a tool is added, renamed, or
    removed."""
    body = client.get("/llms.txt").text
    tools_section = body.split("## Tools", 1)[1].split("## Links", 1)[0]
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
    assert "holds no privileged API key" in body
    assert "X-Api-Key" in body
    assert "https://vulners.com/userinfo" in body
    assert "interactive challenge" in body
    assert "VULNERS_API_KEY" in body
    assert "https://vulners.com/auth.md" in body
    assert "https://mcp.vulners.com/.well-known/mcp/server-card.json" in body


def test_auth_md_describes_the_anonymous_tier(client: TestClient) -> None:
    """VU-1850 anonymous tier: auth.md must document both the bring-your-
    own-key path (full limits) and the anonymous fallback (reduced limits,
    when configured) -- not just the old hard no-key gate."""
    body = client.get("/auth.md").text
    assert "anonymous tier" in body.lower()
    assert str(settings.anon_max_size) in body
    assert "rate limit" in body.lower()
    # Never silently masks a bad caller key with the anon key.
    assert "never silently retried" in body


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
    """VU-1850 anonymous tier: tool invocation is no longer an unconditional
    hard requirement -- a keyless call may run on this deployment's
    anonymous-tier key, with a documented, live-settings-driven size clamp.
    """
    data = client.get("/.well-known/mcp/server-card.json").json()
    auth = data["authentication"]
    assert auth["anonymousDiscovery"] is True
    tool_invocation = auth["toolInvocation"]
    assert tool_invocation["apiKeyHeader"] == "X-Api-Key"
    anon_tier = tool_invocation["anonymousTier"]
    assert anon_tier["allowed"] is True
    assert anon_tier["maxResultSize"] == settings.anon_max_size
    assert anon_tier["rateLimited"] is True
    assert auth["authMdUrl"] == "https://mcp.vulners.com/auth.md"


def test_server_card_tool_invocation_required_true_without_anon_tier(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """VU-1948: ``toolInvocation.required`` must be truthful, not a hardcoded
    ``False``. This deployment's test settings have no anonymous-tier key
    configured (the default -- and, as of writing, prod's actual config
    too), so a keyless ``tools/call`` is rejected: the card must say
    ``required: true``, matching ``auth.resolve_effective_auth``'s
    ``mode == "none"`` gate."""
    monkeypatch.setattr(discovery.settings, "anon_api_key", "")
    data = client.get("/.well-known/mcp/server-card.json").json()
    auth = data["authentication"]
    assert auth["anonymousDiscovery"] is True
    assert auth["toolInvocation"]["required"] is True


def test_server_card_tool_invocation_required_false_with_anon_tier(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When this deployment DOES have a dedicated anon-tier key configured,
    a keyless ``tools/call`` goes through on it (see
    ``auth.resolve_effective_auth``'s ``mode == "anon-tier"`` branch), so the
    card must say ``required: false`` -- the same live setting the auth
    middleware itself reads (``settings.anon_api_key``), not a separate,
    divergent literal."""
    monkeypatch.setattr(discovery.settings, "anon_api_key", "anon-dedicated-key")
    data = client.get("/.well-known/mcp/server-card.json").json()
    auth = data["authentication"]
    assert auth["anonymousDiscovery"] is True
    assert auth["toolInvocation"]["required"] is False


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
    assert {agent["protocol"] for agent in data["agents"]} == {"mcp"}
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
    must resolve to an actual route on the fully composed ASGI app -- not
    just a plausible-looking string. Uses a fresh ``mcp_app`` +
    ``build_asgi_app(target_app=...)`` (no extra routes; MCP is the only
    agent this stack ships) rather than the module-level singleton, per the
    "run once" lifespan constraint documented in
    ``tests/test_asgi_composition.py``.
    """
    fresh_mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    composed = build_asgi_app(target_app=fresh_mcp_app)
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
