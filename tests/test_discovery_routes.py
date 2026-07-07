"""Tests for the agent-discovery HTTP routes served on the MCP subdomain.

They exercise the ASGI app returned by ``FastMCP.http_app()`` (which carries the
``@mcp.custom_route`` handlers) with Starlette's ``TestClient`` and assert that
each new route returns 200, the right content type, and key content markers.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from vulners_mcp.server import mcp


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


def test_robots_txt(client: TestClient) -> None:
    resp = client.get("/robots.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "User-agent: *" in resp.text
    assert "Allow: /" in resp.text
    assert "https://mcp.vulners.com/llms.txt" in resp.text


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


def test_server_card_version_matches_initialize(client: TestClient) -> None:
    """The card's version must equal serverInfo.version from initialize."""
    card = client.get("/.well-known/mcp/server-card.json").json()

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
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
