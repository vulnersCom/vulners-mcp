"""Tests for structured per-call logging emitted by VulnersClient.

Every upstream attempt logs one line with: request_id, upstream path,
status, duration_ms, auth_mode ("keyed"/"anonymous"), a key fingerprint
(first 8 hex chars of sha256(key) — never the raw key), and result size.
"""

from __future__ import annotations

import logging
import re

import httpx

from vulners_mcp.logging_utils import key_fingerprint
from vulners_mcp.vulners_client import VulnersClient

RAW_KEY = "sk-super-secret-vulners-key"


async def _client() -> VulnersClient:
    client = VulnersClient()
    await client.start()
    return client


async def test_keyed_call_logs_expected_fields_and_never_the_raw_key(
    vulners_api, caplog
) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]})
    )
    client = await _client()
    try:
        with caplog.at_level(logging.INFO, logger="vulners_mcp.client"):
            await client.get_supported_os(headers={"X-Api-Key": RAW_KEY})
    finally:
        await client.close()

    [record] = [
        r for r in caplog.records if r.name == "vulners_mcp.client"
    ]
    message = record.getMessage()

    assert "vulners_upstream_call" in message
    assert re.search(r"request_id=[0-9a-f]{32}", message)
    assert "method=GET" in message
    assert "path=/api/v3/audit/getSupportedOS" in message
    assert "status=200" in message
    assert re.search(r"duration_ms=\d+\.\d", message)
    assert "auth_mode=keyed" in message
    expected_fp = key_fingerprint(RAW_KEY)
    assert f"key_fp={expected_fp}" in message
    assert "result_size=" in message
    assert "attempt=1" in message

    # The raw key must never appear anywhere in the log output.
    assert RAW_KEY not in caplog.text


async def test_anonymous_call_logs_auth_mode_anonymous_and_no_fingerprint(
    vulners_api, caplog
) -> None:
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": ["ubuntu"]})
    )
    client = await _client()
    try:
        with caplog.at_level(logging.INFO, logger="vulners_mcp.client"):
            await client.get_supported_os(headers=None)
    finally:
        await client.close()

    [record] = [r for r in caplog.records if r.name == "vulners_mcp.client"]
    message = record.getMessage()
    assert "auth_mode=anonymous" in message
    assert "key_fp=-" in message


def test_key_fingerprint_is_stable_short_and_never_the_raw_key() -> None:
    fp = key_fingerprint(RAW_KEY)
    assert fp is not None
    assert len(fp) == 8
    assert fp == key_fingerprint(RAW_KEY)  # deterministic
    assert fp != key_fingerprint("a-different-key")
    assert RAW_KEY not in fp


def test_key_fingerprint_of_no_key_is_none() -> None:
    assert key_fingerprint(None) is None
    assert key_fingerprint("") is None
