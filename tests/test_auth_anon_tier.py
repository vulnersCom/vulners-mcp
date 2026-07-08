"""Tests for the anonymous tier (VU-1850 "anonymous tier" MR).

A caller who sends no ``X-Api-Key`` still gets their ``tools/call``
forwarded, on a DEDICATED, low-privilege key configured for this deployment
(``settings.anon_api_key``) -- distinct from any human operator's own key,
size-clamped, and rate-limited at the app level. A caller's own key is never
capped here, and a REJECTED caller key is never quietly retried on the anon
key (see ``test_bad_caller_key_is_never_masked_by_the_anon_key`` below).

Full behavior matrix (see also ``tests/test_auth_gate.py`` for the "no anon
tier configured" row):

| Caller                                | Behavior                                            |
|----------------------------------------|-----------------------------------------------------|
| no key, anon key configured            | allowed, forwards anon key, clamped + rate-limited  |
| no key, anon key not configured        | guidance ToolError (test_auth_gate.py)              |
| caller key present, upstream rejects   | sanitized error, NEVER falls back to the anon key   |
| caller key present, valid              | forwarded verbatim, no clamp, no app-level rate limit |
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastmcp.exceptions import ToolError

import vulners_mcp.auth as auth_module
import vulners_mcp.server as server_module
from vulners_mcp.auth import EffectiveAuth, resolve_effective_auth
from vulners_mcp.settings import settings


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    """429 is retriable (see vulners_client._RETRIABLE_STATUS_CODES); this
    module deliberately mocks 429 responses, so keep the suite fast."""

    async def _fake_sleep(seconds: float) -> None:
        return None

    import vulners_mcp.vulners_client as client_module

    monkeypatch.setattr(client_module.asyncio, "sleep", _fake_sleep)


# -------------------- resolve_effective_auth() precedence --------------------


def test_resolve_effective_auth_prefers_caller_key_over_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        auth_module, "get_http_headers", lambda include_all=True: {"X-Api-Key": "caller-key"}
    )
    monkeypatch.setattr(auth_module, "is_http_request", lambda: True)
    monkeypatch.setattr(settings, "anon_api_key", "anon-key")

    result = resolve_effective_auth()

    assert result == EffectiveAuth(headers={"X-Api-Key": "caller-key"}, mode="keyed")
    assert result.is_anon is False


def test_resolve_effective_auth_uses_anon_key_over_http_with_no_caller_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: True)
    monkeypatch.setattr(settings, "anon_api_key", "anon-key")

    result = resolve_effective_auth()

    assert result == EffectiveAuth(headers={"X-Api-Key": "anon-key"}, mode="anon-tier")
    assert result.is_anon is True


def test_resolve_effective_auth_none_over_http_with_no_key_and_no_anon_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: True)
    monkeypatch.setattr(settings, "anon_api_key", "")

    result = resolve_effective_auth()

    assert result == EffectiveAuth(headers=None, mode="none")
    assert result.is_anon is False


def test_resolve_effective_auth_uses_stdio_key_when_not_an_http_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: False)
    monkeypatch.setattr(settings, "stdio_api_key", "owner-key")
    # Must never be picked over the stdio operator's own key.
    monkeypatch.setattr(settings, "anon_api_key", "anon-key")

    result = resolve_effective_auth()

    assert result == EffectiveAuth(headers={"X-Api-Key": "owner-key"}, mode="stdio")


def test_resolve_effective_auth_never_uses_anon_key_outside_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The anon-tier key is an HTTP-transport concept only -- stdio with no
    owner key configured resolves to "stdio-no-key", never the anon key,
    and (unlike HTTP's "none") is never gated -- see AuthMiddleware."""
    monkeypatch.setattr(auth_module, "get_http_headers", lambda include_all=True: {})
    monkeypatch.setattr(auth_module, "is_http_request", lambda: False)
    monkeypatch.setattr(settings, "stdio_api_key", None)
    monkeypatch.setattr(settings, "anon_api_key", "anon-key")

    result = resolve_effective_auth()

    assert result == EffectiveAuth(headers=None, mode="stdio-no-key")
    assert result.is_anon is False


# -------------------- End-to-end: anon tier allowed --------------------


async def test_anon_tier_call_is_forwarded_on_the_anon_key(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )

    async with mcp_streamable_http_client_factory() as client:
        result = await client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
    assert route.calls[0].request.headers["x-api-key"] == "anon-dedicated-key"


async def test_anon_tier_clamps_oversized_size_argument(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    monkeypatch.setattr(settings, "anon_max_size", 10)
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"total": 0, "results": []}}
        )
    )

    async with mcp_streamable_http_client_factory() as client:
        await client.call_tool("search_lucene", {"query": "type:cve", "size": 500})

    assert json.loads(route.calls[0].request.content)["size"] == 10


async def test_anon_tier_leaves_size_within_budget_untouched(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    monkeypatch.setattr(settings, "anon_max_size", 10)
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"total": 0, "results": []}}
        )
    )

    async with mcp_streamable_http_client_factory() as client:
        await client.call_tool("search_lucene", {"query": "type:cve", "size": 5})

    assert json.loads(route.calls[0].request.content)["size"] == 5


async def test_keyed_call_is_never_clamped_even_when_anon_tier_configured(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    monkeypatch.setattr(settings, "anon_max_size", 10)
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"total": 0, "results": []}}
        )
    )

    async with mcp_streamable_http_client_factory({"X-Api-Key": "caller-key"}) as client:
        await client.call_tool("search_lucene", {"query": "type:cve", "size": 500})

    upstream_headers = route.calls[0].request.headers
    assert upstream_headers["x-api-key"] == "caller-key"
    assert json.loads(route.calls[0].request.content)["size"] == 500


# -------------------- Anon-tier app-level rate limit --------------------


async def test_anon_tier_rate_limit_rejects_once_its_bucket_is_empty(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    server_module.auth_middleware.rate_limiter.tokens = 0

    async with mcp_streamable_http_client_factory() as client:
        with pytest.raises(ToolError, match="Anonymous tier quota/rate reached"):
            await client.call_tool("get_supported_os", {})


async def test_keyed_call_bypasses_the_anon_tier_rate_limit(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keyed calls are uncapped at this app layer -- an exhausted anon-tier
    bucket must not block a caller who sent their own key."""
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    server_module.auth_middleware.rate_limiter.tokens = 0
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"ubuntu": ["22.04"]}})
    )

    async with mcp_streamable_http_client_factory({"X-Api-Key": "caller-key"}) as client:
        result = await client.call_tool("get_supported_os", {})

    assert result.data == {"ubuntu": ["22.04"]}
    assert route.calls[0].request.headers["x-api-key"] == "caller-key"


# -------------------- Never mask a bad caller key with the anon key --------------------


async def test_bad_caller_key_is_never_masked_by_the_anon_key(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller who sends their OWN (rejected) key must see a sanitized
    error -- the anon-tier key must never be substituted in behind the
    scenes, even when one is configured for this deployment."""
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(401, json={"result": "ERROR", "data": {}})
    )

    async with mcp_streamable_http_client_factory({"X-Api-Key": "bad-caller-key"}) as client:
        with pytest.raises(ToolError, match="API key missing or rejected"):
            await client.call_tool("get_supported_os", {})

    # Exactly one upstream call, on the caller's own (bad) key -- never
    # retried on the anon key.
    assert route.calls.call_count == 1
    assert route.calls[0].request.headers["x-api-key"] == "bad-caller-key"


async def test_upstream_429_on_the_anon_key_surfaces_anon_tier_guidance(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(429, json={"result": "ERROR", "data": {}})
    )

    async with mcp_streamable_http_client_factory() as client:
        with pytest.raises(ToolError, match="Anonymous tier quota/rate reached"):
            await client.call_tool("get_supported_os", {})


async def test_upstream_429_on_a_caller_key_gets_the_generic_message(
    mcp_streamable_http_client_factory, vulners_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller's own key hitting Vulners' own rate limit is NOT the
    anonymous-tier message -- that would be misleading (this caller already
    sent their own key)."""
    monkeypatch.setattr(settings, "anon_api_key", "anon-dedicated-key")
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(429, json={"result": "ERROR", "data": {}})
    )

    async with mcp_streamable_http_client_factory({"X-Api-Key": "caller-key"}) as client:
        with pytest.raises(ToolError, match="rate limit or quota exceeded") as exc_info:
            await client.call_tool("get_supported_os", {})

    assert "Anonymous tier" not in str(exc_info.value)
