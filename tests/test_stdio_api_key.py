"""Tests for the stdio-only API key fallback (VU-1850 "auth gate" MR).

``settings.stdio_api_key`` (env ``VULNERS_API_KEY``) is the local operator's
own key, used ONLY by the stdio transport (Claude Desktop / a locally-run
server) -- there is no per-request HTTP header in that mode, so the single
local user's own key is the right and only source. On the HTTP transport it
must never be touched, no matter what the deployment's environment holds.

``server._forward_headers()`` decides which branch applies via
``http_context.is_http_request()`` (a live per-call signal: is there an
inbound HTTP request in flight right now), not via the static
``settings.mcp_transport_mode`` string -- see ``http_context`` module
docstring for why that is the more robust choice.

This module also covers ``settings.anon_api_key``'s fallback to the same
``VULNERS_API_KEY`` env var (VU-1850 "discovery truth" MR): unlike
``stdio_api_key``, ``anon_api_key`` DOES reuse it, but only on the HTTP
transport's anonymous tier and only when ``VULNERS_MCP_ANON_API_KEY`` is
unset -- see ``vulners_mcp.settings.Settings.anon_api_key`` and
``tests/test_auth_anon_tier.py`` for the end-to-end behavior this field
feeds.
"""

from __future__ import annotations

import logging

import httpx
import pytest

import vulners_mcp.auth as auth_module
import vulners_mcp.server as server_module
from vulners_mcp.settings import Settings, settings


def test_stdio_api_key_field_reads_vulners_api_key_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNERS_API_KEY", "owner-key")
    fresh = Settings()
    assert fresh.stdio_api_key == "owner-key"


def test_stdio_api_key_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    fresh = Settings()
    assert fresh.stdio_api_key is None


def test_anon_api_key_falls_back_to_vulners_api_key_when_dedicated_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No env change required: an existing deployment's VULNERS_API_KEY now
    also backs the HTTP anonymous tier when VULNERS_MCP_ANON_API_KEY is
    unset (see ``Settings.anon_api_key``'s ``AliasChoices``)."""
    monkeypatch.setenv("VULNERS_API_KEY", "operator-key")
    monkeypatch.delenv("VULNERS_MCP_ANON_API_KEY", raising=False)
    fresh = Settings()
    assert fresh.anon_api_key == "operator-key"


def test_anon_api_key_prefers_dedicated_env_var_when_both_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNERS_API_KEY", "operator-key")
    monkeypatch.setenv("VULNERS_MCP_ANON_API_KEY", "dedicated-anon-key")
    fresh = Settings()
    assert fresh.anon_api_key == "dedicated-anon-key"


def test_anon_api_key_empty_when_neither_env_var_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    monkeypatch.delenv("VULNERS_MCP_ANON_API_KEY", raising=False)
    fresh = Settings()
    assert fresh.anon_api_key == ""


def test_forward_headers_uses_stdio_key_only_when_not_an_http_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stdio-equivalent: no active HTTP request -> falls back to the env key.

    ``_forward_headers`` is a thin wrapper around
    ``auth.resolve_effective_auth()`` -- patch the underlying signals there,
    not on ``server_module`` (which no longer imports them; see
    ``vulners_mcp.auth``).
    """
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: False)
    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")

    assert server_module._forward_headers() == {"X-Api-Key": "owner-key"}


def test_forward_headers_never_uses_stdio_key_on_the_http_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP path: even if the env key is set (operator misconfiguration), a
    request with no caller-supplied header and no anon tier configured must
    forward nothing at all.
    """
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: True)
    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")
    monkeypatch.setattr(settings, "anon_api_key", "")

    assert server_module._forward_headers() is None


def test_forward_headers_prefers_caller_header_over_stdio_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt-and-braces: even in the (impossible in practice) case of a caller
    header showing up while ``is_http_request()`` is False, the explicit
    caller-supplied key always wins over the env fallback.
    """
    monkeypatch.setattr(
        auth_module,
        "get_http_headers",
        lambda include_all=True: {"X-Api-Key": "caller-key"},
    )
    monkeypatch.setattr(auth_module, "is_http_request", lambda: False)
    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")

    assert server_module._forward_headers() == {"X-Api-Key": "caller-key"}


async def test_stdio_mode_end_to_end_uses_owner_key_from_env(
    monkeypatch: pytest.MonkeyPatch, mcp_client, vulners_api
) -> None:
    """``mcp_client`` (in-process, no HTTP request) with a caller who sends no
    key at all: the owner's env key must reach Vulners.
    """
    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )

    result = await mcp_client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
    assert route.calls[0].request.headers["x-api-key"] == "owner-key"


async def test_http_mode_end_to_end_ignores_owner_key_from_env(
    monkeypatch: pytest.MonkeyPatch, mcp_streamable_http_client_factory, vulners_api
) -> None:
    """Full HTTP round trip with the env key set (simulated deployment
    misconfiguration), no anon tier configured, and no caller header: the
    auth gate must still reject the call, and Vulners must never see the
    owner's key.
    """
    from fastmcp.exceptions import ToolError

    from vulners_mcp.auth import NO_API_KEY_MESSAGE

    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")
    monkeypatch.setattr(settings, "anon_api_key", "")

    async with mcp_streamable_http_client_factory() as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool("get_supported_os", {})

    assert str(exc_info.value) == NO_API_KEY_MESSAGE


def test_logs_info_when_anon_tier_falls_back_to_vulners_api_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Only VULNERS_API_KEY set, in HTTP mode: the anon-tier fallback (see
    ``Settings.anon_api_key``) is what's actually engaging, so this gets an
    informational (not warning) log -- and never the key's value."""
    monkeypatch.setenv("VULNERS_API_KEY", "some-key")
    monkeypatch.delenv("VULNERS_MCP_ANON_API_KEY", raising=False)
    monkeypatch.setenv("MCP_TRANSPORT_MODE", "http")
    from vulners_mcp.settings import log_anon_tier_key_source

    with caplog.at_level(logging.INFO, logger="vulners_mcp.settings"):
        log_anon_tier_key_source()

    assert any(
        "VULNERS_API_KEY" in record.message and "anonymous tier" in record.message
        for record in caplog.records
    )
    assert "some-key" not in caplog.text


def test_no_log_when_dedicated_anon_key_also_set(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Both env vars set: VULNERS_MCP_ANON_API_KEY wins outright, so the
    fallback never engages and there is nothing to report."""
    monkeypatch.setenv("VULNERS_API_KEY", "owner-key")
    monkeypatch.setenv("VULNERS_MCP_ANON_API_KEY", "dedicated-anon-key")
    monkeypatch.setenv("MCP_TRANSPORT_MODE", "http")
    from vulners_mcp.settings import log_anon_tier_key_source

    with caplog.at_level(logging.INFO, logger="vulners_mcp.settings"):
        log_anon_tier_key_source()

    assert caplog.records == []


def test_no_log_when_transport_mode_is_stdio(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """stdio using the owner's key is the intended, non-noteworthy case --
    the anonymous tier is an HTTP-only concept."""
    monkeypatch.setenv("VULNERS_API_KEY", "owner-key")
    monkeypatch.delenv("MCP_TRANSPORT_MODE", raising=False)
    from vulners_mcp.settings import log_anon_tier_key_source

    with caplog.at_level(logging.INFO, logger="vulners_mcp.settings"):
        log_anon_tier_key_source()

    assert caplog.records == []


def test_no_log_when_api_key_env_absent_in_http_mode(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    monkeypatch.setenv("MCP_TRANSPORT_MODE", "http")
    from vulners_mcp.settings import log_anon_tier_key_source

    with caplog.at_level(logging.INFO, logger="vulners_mcp.settings"):
        log_anon_tier_key_source()

    assert caplog.records == []
