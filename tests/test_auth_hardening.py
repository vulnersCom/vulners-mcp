"""Tests for the "hard no-key mode" hardening (VU-1850 client-hardening MR).

Covers two related changes:

1. ``VulnersClient`` never injects a server-side fallback API key any more —
   ``settings.vulners_api_key`` doesn't exist, and a caller who sends no key
   gets a request upstream with no ``X-Api-Key`` header at all (Vulners
   rejects it itself; the friendlier MCP-layer gate that replaced that raw
   rejection lives in ``vulners_mcp.auth`` / ``tests/test_auth_gate.py``,
   added in the follow-up VU-1850 "auth gate" MR).
2. ``server._forward_headers()`` forwards only ``X-Api-Key`` upstream —
   ``Authorization`` is never forwarded, so a bearer token meant for the MCP
   host itself can't leak to Vulners.

The stdio-only env-key fallback that ``_forward_headers()`` also implements
is covered separately in ``tests/test_stdio_api_key.py``, along with the
``VULNERS_API_KEY``-outside-stdio startup warning.
"""

from __future__ import annotations

import httpx
import pytest

import vulners_mcp.server as server_module
from vulners_mcp.settings import Settings, settings
from vulners_mcp.vulners_client import VulnersClient


def test_settings_has_no_server_side_api_key_field() -> None:
    """The removed field must actually be gone, not just unused."""
    assert not hasattr(settings, "vulners_api_key")
    assert "vulners_api_key" not in Settings.model_fields


async def test_client_never_injects_a_key_when_caller_sends_none(vulners_api) -> None:
    """No caller key -> no X-Api-Key header at all, ever."""
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]})
    )
    client = VulnersClient()
    await client.start()
    try:
        result = await client.get_supported_os(headers=None)
    finally:
        await client.close()

    assert result == ["ubuntu"]
    upstream_headers = route.calls[0].request.headers
    assert "x-api-key" not in upstream_headers


async def test_client_forwards_caller_supplied_key_verbatim(vulners_api) -> None:
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]})
    )
    client = VulnersClient()
    await client.start()
    try:
        await client.get_supported_os(headers={"X-Api-Key": "caller-key"})
    finally:
        await client.close()

    assert route.calls[0].request.headers["x-api-key"] == "caller-key"


def test_forward_headers_only_forwards_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit-level check of ``_forward_headers`` in isolation from the HTTP stack."""
    monkeypatch.setattr(
        server_module,
        "get_http_headers",
        lambda include_all=True: {
            "Authorization": "Bearer super-secret-token",
            "X-Api-Key": "caller-key",
            "Host": "example.com",
        },
    )
    assert server_module._forward_headers() == {"X-Api-Key": "caller-key"}


def test_forward_headers_returns_none_without_a_caller_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        server_module,
        "get_http_headers",
        lambda include_all=True: {"Authorization": "Bearer super-secret-token"},
    )
    # Hermetic regardless of whether VULNERS_API_KEY happens to be set in the
    # ambient environment this test runs in — see test_stdio_api_key.py for
    # the dedicated stdio-fallback behavior this would otherwise interact with.
    monkeypatch.setattr(settings, "stdio_api_key", None)
    assert server_module._forward_headers() is None


async def test_authorization_header_is_not_forwarded_upstream_end_to_end(
    mcp_streamable_http_client_factory, vulners_api
) -> None:
    """Full round trip: inbound MCP HTTP request carries both Authorization and
    X-Api-Key; respx (standing in for Vulners) must see only X-Api-Key.
    """
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"ubuntu": ["22.04", "24.04"]}}
        )
    )

    async with mcp_streamable_http_client_factory(
        {"Authorization": "Bearer super-secret-token", "X-Api-Key": "caller-key"}
    ) as client:
        result = await client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04", "24.04"]}
    upstream_headers = route.calls[0].request.headers
    assert upstream_headers["x-api-key"] == "caller-key"
    assert "authorization" not in upstream_headers
