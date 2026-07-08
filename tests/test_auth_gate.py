"""Tests for the no-key auth gate (VU-1850 "auth gate" MR).

Product decision: the hosted server (mcp.vulners.com, Streamable HTTP) never
spends a Vulners key on behalf of an anonymous caller.

- ``initialize`` and ``tools/list`` stay open for discovery.
- ``tools/call`` over HTTP without an inbound ``X-Api-Key`` header fails fast
  with a structured ``ToolError`` -- and, critically, nothing is sent
  upstream to Vulners for that call (``vulners_api`` intercepts the upstream
  base URL with ``assert_all_mocked=True``; if the code path under test ever
  made an unmocked request, respx itself would raise and fail the test).
- stdio transport (no HTTP request at all) is never gated.
"""

from __future__ import annotations

import httpx
import pytest
from fastmcp.exceptions import ToolError

from vulners_mcp.auth import NO_API_KEY_MESSAGE


async def test_tool_call_without_key_is_rejected_before_reaching_upstream(
    mcp_streamable_http_client_factory, vulners_api
) -> None:
    """No X-Api-Key header -> ToolError, and no request reaches Vulners.

    ``vulners_api`` has zero routes registered here on purpose: if the auth
    gate failed to block the call and the tool proceeded to call Vulners,
    respx (``assert_all_mocked=True``) would raise on the unmocked request
    instead of this test's own assertion ever running.
    """
    async with mcp_streamable_http_client_factory() as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool("get_supported_os", {})

    assert str(exc_info.value) == NO_API_KEY_MESSAGE


async def test_error_message_is_uniform_across_tools(
    mcp_streamable_http_client_factory, vulners_api
) -> None:
    """Same guidance text regardless of which of the 7 tools was called."""
    async with mcp_streamable_http_client_factory() as client:
        for tool_name, args in (
            ("get_supported_os", {}),
            ("search_lucene", {"query": "type:cve"}),
            ("bulletin_by_id", {"id": "CVE-2024-3094"}),
        ):
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool(tool_name, args)
            assert str(exc_info.value) == NO_API_KEY_MESSAGE


async def test_tool_call_with_key_is_forwarded_normally(
    mcp_streamable_http_client_factory, vulners_api
) -> None:
    """A caller-supplied X-Api-Key still works exactly as before the gate."""
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"ubuntu": ["22.04", "24.04"]}}
        )
    )

    async with mcp_streamable_http_client_factory({"X-Api-Key": "caller-key"}) as client:
        result = await client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04", "24.04"]}
    assert route.calls[0].request.headers["x-api-key"] == "caller-key"


async def test_initialize_and_tools_list_stay_open_without_a_key(
    mcp_streamable_http_client_factory,
) -> None:
    """Discovery (initialize + tools/list) must never require a key.

    Entering the client context performs the ``initialize`` handshake; if the
    gate wrongly applied there, this would already raise.
    """
    async with mcp_streamable_http_client_factory() as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    assert tool_names == {
        "bulletin_by_id",
        "search_lucene",
        "audit_software",
        "get_supported_os",
        "audit_linux_packages",
        "query_autocomplete",
        "search_cpe",
    }


async def test_stdio_transport_is_never_gated(mcp_client, vulners_api) -> None:
    """``mcp_client`` drives the server in-process with no HTTP request at all
    (the stdio-equivalent code path) -- a keyless tools/call must succeed,
    not raise the HTTP-only ToolError.
    """
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )

    result = await mcp_client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
    assert "x-api-key" not in route.calls[0].request.headers
