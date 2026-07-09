"""Tests for timeout configuration and the retry/backoff policy.

Retry policy: up to 3 total attempts (1 initial + 2 retries), with
exponential backoff + jitter, on 429/502/503/504 and httpx connect errors,
honoring ``Retry-After``. No retry on any other 4xx.
"""

from __future__ import annotations

import httpx
import pytest

from vulners_mcp.settings import Settings
from vulners_mcp.vulners_client import ApiError, VulnersClient


async def _client() -> VulnersClient:
    client = VulnersClient()
    await client.start()
    return client


def test_default_timeouts() -> None:
    s = Settings()
    assert s.vulners_connect_timeout_seconds == 5.0
    assert s.vulners_read_timeout_seconds == 30.0


def test_timeouts_are_env_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNERS_CONNECT_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("VULNERS_READ_TIMEOUT_SECONDS", "45")
    s = Settings()
    assert s.vulners_connect_timeout_seconds == 2.5
    assert s.vulners_read_timeout_seconds == 45.0


async def test_client_builds_httpx_timeout_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNERS_CONNECT_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("VULNERS_READ_TIMEOUT_SECONDS", "9")
    # VulnersClient reads the module-level `settings` singleton, so patch it
    # directly rather than relying on env vars set after import time.
    import vulners_mcp.vulners_client as client_module

    monkeypatch.setattr(client_module.settings, "vulners_connect_timeout_seconds", 1.0)
    monkeypatch.setattr(client_module.settings, "vulners_read_timeout_seconds", 9.0)

    client = VulnersClient()
    await client.start()
    try:
        timeout = client._client.timeout
        assert timeout.connect == 1.0
        assert timeout.read == 9.0
    finally:
        await client.close()


@pytest.fixture(autouse=True)
def _no_real_sleeping(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the backoff sleep with a no-op that records requested delays.

    Keeps the suite fast and deterministic while still letting tests assert
    on the delay that *would* have been used (e.g. honoring Retry-After).
    """
    delays: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    import vulners_mcp.vulners_client as client_module

    monkeypatch.setattr(client_module.asyncio, "sleep", _fake_sleep)
    return delays


async def test_retries_on_503_then_succeeds(vulners_api) -> None:
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        side_effect=[
            httpx.Response(503, text="upstream busy"),
            httpx.Response(503, text="upstream busy"),
            httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]}),
        ]
    )
    client = await _client()
    try:
        result = await client.get_supported_os()
    finally:
        await client.close()

    assert result == ["ubuntu"]
    assert route.calls.call_count == 3


async def test_no_retry_on_400(vulners_api) -> None:
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(400, text="bad request")
    )
    client = await _client()
    try:
        with pytest.raises(ApiError) as excinfo:
            await client.get_supported_os()
    finally:
        await client.close()

    assert excinfo.value.status == 400
    assert route.calls.call_count == 1


async def test_exhausts_retries_and_raises(vulners_api) -> None:
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(503, text="upstream busy")
    )
    client = await _client()
    try:
        with pytest.raises(ApiError):
            await client.get_supported_os()
    finally:
        await client.close()

    assert route.calls.call_count == 3


async def test_retries_on_connect_error_then_succeeds(vulners_api) -> None:
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        side_effect=[
            httpx.ConnectError("connection refused"),
            httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]}),
        ]
    )
    client = await _client()
    try:
        result = await client.get_supported_os()
    finally:
        await client.close()

    assert result == ["ubuntu"]
    assert route.calls.call_count == 2


async def test_no_retry_on_read_timeout(vulners_api) -> None:
    """Only *connect* errors are retried — a read timeout might mean the
    upstream already processed the request, so retrying blindly is unsafe.
    It still surfaces as a sanitized ApiError, not a raw httpx exception."""
    route = vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        side_effect=httpx.ReadTimeout("timed out")
    )
    client = await _client()
    try:
        with pytest.raises(ApiError) as excinfo:
            await client.get_supported_os()
    finally:
        await client.close()

    assert excinfo.value.status == 0
    assert route.calls.call_count == 1


async def test_retry_honors_retry_after_header(
    vulners_api, _no_real_sleeping: list[float]
) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}, text="slow down"),
            httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]}),
        ]
    )
    client = await _client()
    try:
        result = await client.get_supported_os()
    finally:
        await client.close()

    assert result == ["ubuntu"]
    assert _no_real_sleeping == [7.0]
