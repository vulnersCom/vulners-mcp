"""Tests for stateless Streamable HTTP (VU-1850 "auth gate" MR).

The hosted server (mcp.vulners.com) sets ``stateless_http=True`` (settings-
driven: ``MCP_STATELESS_HTTP``, default true) so it can scale horizontally
behind a load balancer with no sticky session routing: every request gets
its own transport, with no server-side ``mcp-session-id`` continuity
required between calls.

Each test below builds its own fresh ``mcp.http_app(...)`` (same call
``vulners_mcp.asgi`` makes for the real, module-level ``mcp_app``) rather
than reusing that singleton: a Streamable HTTP session manager's lifespan
can only be entered once per instance, and each test's ``TestClient``
context enters its app's lifespan independently.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from vulners_mcp.server import mcp
from vulners_mcp.settings import settings


@pytest.fixture
def client() -> TestClient:
    fresh_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    with TestClient(fresh_app) as test_client:
        yield test_client


def test_stateless_http_is_the_default() -> None:
    assert settings.mcp_stateless_http is True


def _initialize_request(request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    }


def _post(client: TestClient, body: dict, session_id: str | None = None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return client.post("/mcp/", headers=headers, content=json.dumps(body))


def _sse_payload(resp) -> dict:
    for line in resp.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:") :].strip())
    raise AssertionError(f"no SSE data frame in response: {resp.text!r}")


def test_two_independent_initialize_calls_both_succeed_with_no_session_continuity(
    client: TestClient,
) -> None:
    """Stateless semantics: two fresh initialize POSTs, no shared session id
    between them, both succeed. A stateful server would still *accept* two
    initializes, so the real signal here is that neither response depends on
    (or requires) a prior mcp-session-id -- neither POST below sends one.
    """
    resp1 = _post(client, _initialize_request(1))
    resp2 = _post(client, _initialize_request(2))

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert _sse_payload(resp1)["result"]["serverInfo"]["name"] == "Vulners MCP"
    assert _sse_payload(resp2)["result"]["serverInfo"]["name"] == "Vulners MCP"


def test_tools_list_works_on_a_fresh_request_without_prior_initialize(
    client: TestClient,
) -> None:
    """In stateful mode a server may reject a request outside a known
    session; in stateless mode each request stands alone.
    """
    tools_list_request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = _post(client, tools_list_request)

    assert resp.status_code == 200
    payload = _sse_payload(resp)
    assert "result" in payload, payload
    tool_names = {t["name"] for t in payload["result"]["tools"]}
    assert "bulletin_by_id" in tool_names


def test_mcp_app_is_built_with_stateless_http_from_settings() -> None:
    """The real, module-level app object (``vulners_mcp.asgi.mcp_app``)
    actually carries the settings-driven flag -- guards against the
    composition silently reverting to fastmcp's own stateful default of
    ``stateless_http=False``. Pure attribute introspection: does not enter
    the app's lifespan, so it doesn't touch the "run once" budget spent in
    ``tests/test_asgi_composition.py``.
    """
    from vulners_mcp.asgi import mcp_app

    mcp_route = next(r for r in mcp_app.routes if getattr(r, "path", None) == "/mcp")
    session_manager = mcp_route.endpoint.session_manager
    assert session_manager.stateless is True
