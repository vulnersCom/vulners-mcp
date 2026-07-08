"""Tests for unwrapping the Vulners ``{"result": "OK", "data": ...}`` envelope,
and for the output-model declarations that used to lie about tool shapes.

Vulners API responses are always shaped ``{"result": "OK", "data": {...}}``
(or, per docs.vulners.com, sometimes ``data`` is a bare array rather than an
object — see ``test_search_lucene_tolerates_array_shaped_upstream_payload``
below). ``VulnersClient`` methods must return ``data`` on success and raise
``ApiError`` otherwise.
"""

from __future__ import annotations

import json

import httpx
import pytest

from vulners_mcp.vulners_client import ApiError, VulnersClient

# Tools whose declared pydantic output model didn't match the real Vulners
# response shape (flagged by "# TODO: fix model to match actual response
# structure" before this MR). Their MCP tool definitions must not advertise a
# strict object output schema any more -- see server.py's `-> Any` return
# annotations and the "# TODO(MR tool-contract)" markers.
FORMERLY_MISDECLARED_TOOLS = {
    "search_lucene",
    "audit_linux_packages",
    "query_autocomplete",
    "search_cpe",
}


async def _client() -> VulnersClient:
    client = VulnersClient()
    await client.start()
    return client


async def test_ok_envelope_unwraps_to_data(vulners_api) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}}
        )
    )
    client = await _client()
    try:
        result = await client.get_supported_os()
    finally:
        await client.close()

    assert result == {"ubuntu": ["22.04"]}


async def test_non_ok_result_raises_api_error(vulners_api) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(
            200, json={"result": "ERROR", "data": {"error": "bad query"}}
        )
    )
    client = await _client()
    try:
        with pytest.raises(ApiError) as excinfo:
            await client.get_supported_os()
    finally:
        await client.close()

    assert excinfo.value.status == 200


async def test_http_error_status_raises_api_error(vulners_api) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(401, json={"result": "ERROR", "message": "no key"})
    )
    client = await _client()
    try:
        with pytest.raises(ApiError) as excinfo:
            await client.get_supported_os()
    finally:
        await client.close()

    assert excinfo.value.status == 401


async def test_unenveloped_body_passes_through_unchanged(vulners_api) -> None:
    """A handful of endpoints might not use the envelope at all; tolerate that."""
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json=["ubuntu", "debian"])
    )
    client = await _client()
    try:
        result = await client.get_supported_os()
    finally:
        await client.close()

    assert result == ["ubuntu", "debian"]


async def test_declared_output_models_removed_for_formerly_misdeclared_tools(
    mcp_client,
) -> None:
    """These tools must no longer advertise a strict pydantic object schema.

    ``FastMCP`` derives ``outputSchema`` from a tool's declared return type
    annotation. When that annotation was a pydantic ``BaseModel`` shaped
    differently from the real Vulners payload, a real (non-object-shaped)
    response made `tools/call` blow up server-side with "structured_content
    must be a dict" (see the repro in
    ``test_search_lucene_tolerates_array_shaped_upstream_payload``). The fix
    for this MR is to stop declaring a schema at all for these tools.
    """
    tools = {tool.name: tool for tool in await mcp_client.list_tools()}
    for name in FORMERLY_MISDECLARED_TOOLS:
        assert tools[name].outputSchema is None, (
            f"{name} still advertises an output schema; it should return Any "
            "until a fixture-accurate contract ships (see the "
            "'TODO(MR tool-contract)' markers in server.py)"
        )


async def test_search_lucene_tolerates_array_shaped_upstream_payload(
    mcp_client, vulners_api
) -> None:
    """Regression test for the exact failure this MR fixes.

    Per docs.vulners.com, ``/api/v3/search/lucene`` can return its ``data``
    as a bare array of bulletins, not the ``{total, skip, size, results}``
    object the old ``LuceneSearchResponse`` model declared. Before this MR,
    that shape made `tools/call` raise a ``ToolError`` server-side (a real
    upstream response would have broken every caller):
    ``ValueError: structured_content must be a dict or None. Got list: [...]``.

    It must now succeed. Note it comes back via ``result.content`` (plain
    text/JSON), not ``result.structured_content``/``result.data`` — the MCP
    spec requires structured content to be a JSON *object*, so an
    array-shaped payload can only ride as unstructured content once no
    output schema is declared. Making array-shaped tool results available as
    structured content too is exactly the "fixture-accurate contract" left
    for the follow-up MR.
    """
    bulletins = [
        {"id": "CVE-2024-0001", "title": "Example", "type": "cve"},
        {"id": "CVE-2024-0002", "title": "Another example", "type": "cve"},
    ]
    vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": bulletins})
    )

    result = await mcp_client.call_tool("search_lucene", {"query": "type:cve"})

    assert result.is_error is False
    assert json.loads(result.content[0].text) == bulletins
