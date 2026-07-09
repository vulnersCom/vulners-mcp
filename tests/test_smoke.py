"""Smoke tests proving the server boots, advertises its tools correctly, and
that the test harness itself (in-process client + respx interception) works.

These are intentionally shallow: deeper, tool-specific behaviour belongs in
dedicated test modules. The point here is a fast, always-green sanity check
that CI can gate on.
"""

from __future__ import annotations

import fastmcp.exceptions
import httpx
import jsonschema
import pytest
from fastmcp import Client
from starlette.testclient import TestClient

from vulners_mcp import __version__

KNOWN_TOOLS = {
    "bulletin_by_id",
    "search_lucene",
    "audit_software",
    "get_supported_os",
    "audit_linux_packages",
    "query_autocomplete",
    "search_cpe",
}

# Minimal shape check for the bulletin_by_id fixture payload — enough to
# catch an accidental typo in the fixture without pinning every field.
BULLETIN_SCHEMA = {
    "type": "object",
    "required": ["id", "title", "type"],
    "properties": {
        "id": {"type": "string"},
        "title": {"type": "string"},
        "type": {"type": "string"},
    },
}


async def test_initialize_reports_package_version(mcp_client: Client) -> None:
    """The MCP handshake must report the same version as the installed package."""
    server_info = mcp_client.initialize_result.serverInfo
    assert server_info.name == "Vulners MCP"
    assert server_info.version == __version__


async def test_tools_list_returns_exactly_the_known_tools(mcp_client: Client) -> None:
    tools = await mcp_client.list_tools()
    assert {tool.name for tool in tools} == KNOWN_TOOLS
    assert len(tools) == 7


async def test_tools_call_uses_mocked_upstream_not_the_network(
    mcp_client: Client, vulners_api, load_fixture
) -> None:
    """`tools/call` must go through httpx -> respx, never a real socket.

    Mocks the Vulners `/api/v3/search/id` endpoint that `bulletin_by_id`
    calls and asserts the tool returns exactly the mocked payload, unwrapped
    from the real Vulners `{"result": "OK", "data": ...}` envelope. This
    proves both that the respx fixture is correctly wired into the client
    used by the running server, and that `VulnersClient` unwraps `data`
    rather than handing back the raw envelope.
    """
    payload = load_fixture("bulletin_by_id_response.json")
    jsonschema.validate(payload, BULLETIN_SCHEMA)
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": payload})
    )

    result = await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2024-0001"})

    assert route.called
    assert route.calls.call_count == 1
    assert result.data == payload


async def test_tools_call_unmocked_route_never_hits_the_network(
    mcp_client: Client, vulners_api
) -> None:
    """A request to a route nobody mocked must fail fast, not go out to the internet.

    ``vulners_api`` is built with ``assert_all_mocked=True``, so respx raises
    ``AllMockedAssertionError`` for any request that doesn't match a
    configured route, instead of letting it fall through to a real socket.
    fastmcp logs and re-raises tool exceptions as a plain ``ToolError`` with
    only a message (no exception chaining survives that boundary), so assert
    on the respx error text rather than the original exception type.
    """
    with pytest.raises(fastmcp.exceptions.ToolError, match="not mocked"):
        await mcp_client.call_tool("get_supported_os", {})


def test_health_route_over_http(mcp_http_client: TestClient) -> None:
    """Sanity check for the ``mcp_http_client`` fixture itself: the plain
    ``/health`` custom route (unrelated to any Vulners API call) must respond
    over the Starlette ``TestClient`` wrapping ``mcp.http_app()``.
    """
    resp = mcp_http_client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "OK"
