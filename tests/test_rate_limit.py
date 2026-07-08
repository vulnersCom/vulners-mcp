"""Smoke test for the anon-tier rate limiter (VU-1850 "anonymous tier" MR).

The rate limiter lives on ``AuthMiddleware`` (see ``vulners_mcp.auth``) and
applies ONLY to calls running on the shared anonymous-tier key -- a caller
who sends their own ``X-Api-Key`` is never capped at this layer. Per-IP/
per-caller limiting for keyed traffic belongs at the Cloudflare edge in
front of mcp.vulners.com; this is just an abuse-of-last-resort belt
protecting the shared anon-tier key's quota.

Full end-to-end anon-vs-keyed rate-limit behavior (bucket exhausted, keyed
calls bypass it) lives in ``tests/test_auth_anon_tier.py``; this module is
a narrower smoke test that the limiter itself is wired up with the
settings-driven rate and actually rejects once its bucket is empty.
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

import vulners_mcp.server as server_module
from vulners_mcp.settings import settings


def test_anon_rate_limiter_is_attached_with_the_settings_driven_rps() -> None:
    bucket = server_module.auth_middleware.rate_limiter
    assert bucket.refill_rate == settings.mcp_rate_limit_rps
    assert bucket.capacity == max(1, int(settings.mcp_rate_limit_rps * 2))


async def test_anon_rate_limiter_rejects_once_its_bucket_is_empty(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    bucket = server_module.auth_middleware.rate_limiter
    bucket.tokens = 0  # simulate an exhausted burst allowance

    async with mcp_streamable_http_client_factory() as client:
        with pytest.raises(ToolError, match=r"(?i)rate.?limit|quota"):
            await client.call_tool("get_supported_os", {})


async def test_anon_rate_limiter_allows_calls_within_budget(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )
    bucket = server_module.auth_middleware.rate_limiter
    bucket.tokens = bucket.capacity

    async with mcp_streamable_http_client_factory() as client:
        result = await client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
