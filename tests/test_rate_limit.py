"""Smoke test for the global rate limiter (VU-1850 "auth gate" MR).

Per-IP/per-caller limiting belongs at the Cloudflare edge in front of
mcp.vulners.com (fastmcp's ``RateLimitingMiddleware`` has no notion of a
caller identity beyond what we'd supply ourselves, and inferring one from
proxied headers is out of scope here) -- this is just an abuse-of-last-resort
belt: a single, generous, global requests-per-second ceiling.

This is deliberately a smoke test, not an exhaustive one: it proves the
middleware is wired up and actually rejects once its bucket is empty, without
asserting on token-bucket refill timing math (fastmcp already tests the
bucket implementation itself).
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

import vulners_mcp.server as server_module
from vulners_mcp.settings import settings


def test_rate_limiter_is_attached_with_the_settings_driven_rps() -> None:
    assert server_module.rate_limiter.max_requests_per_second == settings.mcp_rate_limit_rps
    assert server_module.rate_limiter.global_limit is True
    assert server_module.rate_limiter in server_module.mcp.middleware


async def test_rate_limiter_rejects_once_its_bucket_is_empty(mcp_client, vulners_api) -> None:
    bucket = server_module.rate_limiter.global_limiter
    bucket.tokens = 0  # simulate an exhausted burst allowance

    with pytest.raises(ToolError, match=r"(?i)rate limit"):
        await mcp_client.call_tool("get_supported_os", {})


async def test_rate_limiter_allows_calls_within_budget(mcp_client, vulners_api) -> None:
    import httpx

    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )
    bucket = server_module.rate_limiter.global_limiter
    bucket.tokens = bucket.capacity

    result = await mcp_client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
