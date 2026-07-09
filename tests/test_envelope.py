"""Tests for unwrapping the Vulners response envelope, and for the
output-model declarations that used to lie about tool shapes.

Vulners uses two different envelope shapes depending on API version:

- v3 endpoints (``/api/v3/...``) are shaped ``{"result": "OK", "data": {...}}``
  (or, per docs.vulners.com, sometimes ``data`` is a bare array rather than an
  object — see ``test_search_lucene_tolerates_array_shaped_upstream_payload``
  below). On success, ``VulnersClient`` methods must return ``data``.
- v4 endpoints (``/api/v4/...``) put the payload directly in ``result`` with
  no ``"OK"``/``data`` wrapper (see ``test_unwrap_v4_dict``,
  ``test_unwrap_v4_list``, ``test_unwrap_v4_cpe`` below — this is the
  regression guard for the prod incident where 3 of 7 tools
  (``audit_linux_packages``, ``audit_software``, ``search_cpe``) were dead
  because ``_unwrap`` only recognized the v3 shape and treated every v4
  ``result`` as a rejected request). On success, ``VulnersClient`` methods
  must return ``result`` itself.

Either way, a genuine error (a non-container, non-"OK" ``result``, or an HTTP
error status) must still raise ``ApiError``.
"""

from __future__ import annotations

import json

import httpx
import pytest

from vulners_mcp.vulners_client import ApiError, VulnersClient

# Tools whose declared output type didn't match the real Vulners response
# shape (flagged by "# TODO: fix model to match actual response structure"
# before this MR). Their MCP tool definitions must not advertise a strict
# object output schema any more -- see server.py's `-> Any` return
# annotations and the "# TODO(MR tool-contract)" markers.
#
# ``audit_software`` joined this set as part of the VU-1850/VU-1946 hotfix:
# its declared return type was `Dict[str, Any]`, but the real
# ``/api/v4/audit/software`` payload is a bare list (one entry per input
# software item) -- previously masked by the v3/v4 envelope bug (every call
# raised ApiError before the response shape even mattered), it surfaced as
# soon as that bug was fixed: FastMCP raised
# ``ValueError: structured_content must be a dict or None. Got list: [...]``
# for every real (list-shaped) response, exactly like the pre-existing
# ``search_lucene`` array-payload case below.
FORMERLY_MISDECLARED_TOOLS = {
    "search_lucene",
    "audit_linux_packages",
    "audit_software",
    "query_autocomplete",
    "search_cpe",
}


async def _client() -> VulnersClient:
    client = VulnersClient()
    await client.start()
    return client


async def test_unwrap_v3_ok(vulners_api) -> None:
    """v3 envelope: ``result == "OK"`` -> return ``data``."""
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


async def test_unwrap_v4_dict(vulners_api, load_fixture) -> None:
    """v4 envelope (dict payload): ``/api/v4/audit/linux`` real recorded shape.

    Real upstream response is ``{"result": {"issues": [...], "errors": {},
    "totalPackages": N}}`` -- no ``"OK"``/``data`` wrapper. Before the fix,
    ``_unwrap`` treated the dict ``result`` as a rejected request and raised
    ApiError on every call; it must now return the dict payload.
    """
    body = load_fixture("audit_linux_v4.json")
    vulners_api.post("/api/v4/audit/linux").mock(
        return_value=httpx.Response(200, json=body)
    )
    client = await _client()
    try:
        result = await client.audit_linux_packages({"os_name": "ubuntu", "os_version": "22.04", "packages": ["openssl 3.0.2 amd64"]})
    finally:
        await client.close()

    assert result == body["result"]
    assert result["totalPackages"] == 1
    assert result["issues"][0]["package"] == "openssl 3.0.2 amd64"


async def test_unwrap_v4_list(vulners_api, load_fixture) -> None:
    """v4 envelope (list payload): ``/api/v4/audit/software`` real recorded shape.

    Real upstream response is ``{"result": [{"input": ..., "vulnerabilities":
    [...]}]}`` -- the list itself is the payload, not an error.
    """
    body = load_fixture("audit_software_v4.json")
    vulners_api.post("/api/v4/audit/software").mock(
        return_value=httpx.Response(200, json=body)
    )
    client = await _client()
    try:
        result = await client.audit_software({"software": [{"part": "a", "vendor": "openssl", "product": "openssl", "version": "1.0.1g"}]})
    finally:
        await client.close()

    assert result == body["result"]
    assert isinstance(result, list)
    assert result[0]["input"]["vendor"] == "openssl"
    assert len(result[0]["vulnerabilities"]) > 0


async def test_unwrap_v4_cpe(vulners_api, load_fixture) -> None:
    """v4 envelope (dict payload): ``/api/v4/search/cpe`` real recorded shape."""
    body = load_fixture("search_cpe_v4.json")
    vulners_api.get("/api/v4/search/cpe").mock(
        return_value=httpx.Response(200, json=body)
    )
    client = await _client()
    try:
        result = await client.search_cpe(vendor="openssl", product="openssl")
    finally:
        await client.close()

    assert result == body["result"]
    assert result["best_match"] == "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
    assert len(result["cpe"]) > 0


async def test_unwrap_v4_genuine_error_still_raises(vulners_api) -> None:
    """A genuine v4 error (result is a plain error string, not a container) still raises."""
    vulners_api.post("/api/v4/audit/linux").mock(
        return_value=httpx.Response(200, json={"result": "bad request"})
    )
    client = await _client()
    try:
        with pytest.raises(ApiError) as excinfo:
            await client.audit_linux_packages({"os_name": "ubuntu", "os_version": "22.04", "packages": []})
    finally:
        await client.close()

    assert excinfo.value.status == 200


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
