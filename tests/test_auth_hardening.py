"""Tests for the "hard no-key mode" hardening (VU-1850 client-hardening MR).

Covers two related changes:

1. ``VulnersClient`` never injects a server-side fallback API key any more —
   ``settings.vulners_api_key`` doesn't exist, and a caller who sends no key
   gets a request upstream with no ``X-Api-Key`` header at all (Vulners
   rejects it itself; a friendlier MCP-layer gate ships in a later MR).
2. ``server._forward_headers()`` forwards only ``X-Api-Key`` upstream —
   ``Authorization`` is never forwarded, so a bearer token meant for the MCP
   host itself can't leak to Vulners.
"""

from __future__ import annotations

import logging

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


def test_warns_when_legacy_api_key_env_var_is_set(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("VULNERS_API_KEY", "some-legacy-key")
    from vulners_mcp.settings import warn_if_legacy_api_key_env_set

    with caplog.at_level(logging.WARNING, logger="vulners_mcp.settings"):
        warn_if_legacy_api_key_env_set()

    assert any(
        "VULNERS_API_KEY" in record.message and "ignored" in record.message
        for record in caplog.records
    )
    assert "some-legacy-key" not in caplog.text


def test_no_warning_when_legacy_api_key_env_var_is_absent(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    from vulners_mcp.settings import warn_if_legacy_api_key_env_set

    with caplog.at_level(logging.WARNING, logger="vulners_mcp.settings"):
        warn_if_legacy_api_key_env_set()

    assert caplog.records == []
