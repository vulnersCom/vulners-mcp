"""VU-2404: tool input schemas must be usable in OpenAI strict mode.

The OpenAI Responses API turns ``strict`` on by default for function tools,
and strict mode needs every object to declare its ``properties``. Before this
fix ``audit_software`` and ``query_autocomplete`` took a free-form
``body: Dict[str, Any]`` -- ``{"type": "object", "additionalProperties":
true}`` -- which no client-side converter can tighten, so the whole Responses
API request failed with HTTP 400 ``invalid_function_parameters``.

``body`` is now typed with closed Pydantic models, keeping the
``{"body": {...}}`` call shape for existing callers. Strict-mode callers send
every optional field, as ``null`` when unused, and the Vulners API rejects
``null`` in CPE fields, so ``audit_software`` must strip those before sending.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Iterator

import httpx
import pytest


async def _input_schemas(mcp_client) -> dict[str, dict[str, Any]]:
    return {tool.name: tool.inputSchema for tool in await mcp_client.list_tools()}


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _is_open_object(node: dict[str, Any]) -> bool:
    additional = node.get("additionalProperties")
    if additional is True or isinstance(additional, dict):
        return True
    return node.get("type") == "object" and "properties" not in node


async def test_no_tool_input_schema_contains_an_open_object(mcp_client) -> None:
    for name, schema in (await _input_schemas(mcp_client)).items():
        open_objects = [node for node in _walk(schema) if _is_open_object(node)]
        assert open_objects == [], f"{name} has an open object: {open_objects}"


async def test_every_tool_input_schema_converts_to_openai_strict(mcp_client) -> None:
    strict_schema = pytest.importorskip("agents.strict_schema")

    for name, schema in (await _input_schemas(mcp_client)).items():
        try:
            strict_schema.ensure_strict_json_schema(copy.deepcopy(schema))
        except Exception as exc:  # noqa: BLE001 -- report which tool broke
            pytest.fail(f"{name} is not strict-compatible: {exc}")


async def test_audit_software_does_not_send_nulls_to_the_api(
    mcp_client, vulners_api, load_fixture
) -> None:
    """A strict-mode model fills every optional field, unused ones as null."""
    route = vulners_api.post("/api/v4/audit/software").mock(
        return_value=httpx.Response(200, json=load_fixture("audit_software_v4.json"))
    )
    cpe = {
        "part": "a",
        "vendor": "openssl",
        "product": "openssl",
        "version": "1.0.1g",
        "update": None,
        "edition": None,
        "language": None,
        "sw_edition": None,
        "target_sw": None,
        "target_hw": None,
        "other": None,
    }

    result = await mcp_client.call_tool(
        "audit_software", {"body": {"software": [cpe], "match": None}}
    )

    assert result.is_error is False
    sent = json.loads(route.calls[0].request.content)
    assert "match" not in sent
    assert sent["software"] == [
        {"part": "a", "vendor": "openssl", "product": "openssl", "version": "1.0.1g"}
    ]


async def test_audit_software_still_accepts_cpe_strings(
    mcp_client, vulners_api, load_fixture
) -> None:
    route = vulners_api.post("/api/v4/audit/software").mock(
        return_value=httpx.Response(200, json=load_fixture("audit_software_v4.json"))
    )
    cpe = "cpe:2.3:a:openssl:openssl:1.0.1g:*:*:*:*:*:*:*"

    await mcp_client.call_tool("audit_software", {"body": {"software": [cpe]}})

    sent = json.loads(route.calls[0].request.content)
    assert sent["software"] == [cpe]


async def test_audit_software_tolerates_the_legacy_platform_field(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Older docs told models to send ``platform``, which is not a CPE field.
    The API silently dropped it; callers following those docs must keep
    working, and the field must not reach the API.
    """
    route = vulners_api.post("/api/v4/audit/software").mock(
        return_value=httpx.Response(200, json=load_fixture("audit_software_v4.json"))
    )
    cpe = {
        "part": "a",
        "vendor": "openssl",
        "product": "openssl",
        "version": "1.0.1g",
        "platform": "*",
    }

    result = await mcp_client.call_tool(
        "audit_software", {"body": {"software": [cpe], "match": "full"}}
    )

    assert result.is_error is False
    sent = json.loads(route.calls[0].request.content)
    assert sent["match"] == "full"
    assert "platform" not in sent["software"][0]


async def test_audit_software_documents_sw_edition_not_platform(mcp_client) -> None:
    tool = next(t for t in await mcp_client.list_tools() if t.name == "audit_software")
    text = tool.description + json.dumps(tool.inputSchema)

    assert "sw_edition" in text
    assert "platform" not in text
