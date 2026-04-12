"""Integration tests for Vulners MCP server — hits the real Vulners API.

Run with: uv run pytest tests/test_integration.py -v -s
Requires VULNERS_API_KEY in .env or environment.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from dotenv import load_dotenv

load_dotenv()

from vulners_mcp.vulners_client import VulnersClient


@pytest.fixture(scope="module")
def api_key():
    key = os.environ.get("VULNERS_API_KEY", "")
    if not key:
        pytest.skip("VULNERS_API_KEY not set")
    return key


@pytest_asyncio.fixture
async def client(api_key):
    c = VulnersClient(api_key=api_key)
    await c.start()
    yield c
    await c.close()


# ── bulletin_by_id (single) ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bulletin_by_id_single(client):
    result = await client.search_by_id(
        {"id": "CVE-2021-44228", "references": True, "fields": ["*"]}
    )
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    docs = result["data"]["documents"]
    assert "CVE-2021-44228" in docs
    doc = docs["CVE-2021-44228"]
    assert "title" in doc
    assert "description" in doc
    print(f"\n  [bulletin single] title: {doc.get('title')}")


# ── bulletin_by_id (list) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bulletin_by_id_list(client):
    ids = ["CVE-2021-44228", "CVE-2024-3094"]
    result = await client.search_by_id(
        {"id": ids, "references": False, "fields": ["*"]}
    )
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    docs = result["data"]["documents"]
    assert len(docs) == 2
    for cve_id in ids:
        assert cve_id in docs
    print(f"\n  [bulletin list] IDs: {list(docs.keys())}")


# ── search_lucene ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_lucene(client):
    result = await client.search_lucene(
        {"query": "type:cve AND cnaAffected.vendor:apache", "size": 3, "fields": ["*"]}
    )
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    data = result["data"]
    assert data["total"] > 0
    search_results = data.get("search", [])
    assert len(search_results) > 0
    # Each result should have basic fields
    first = search_results[0]
    assert "id" in first or "_id" in first
    print(f"\n  [search_lucene] total: {data['total']}, returned: {len(search_results)}")


@pytest.mark.asyncio
async def test_search_lucene_date_range(client):
    result = await client.search_lucene(
        {
            "query": "type:cve AND cvss.score:[9 TO 10] AND published:[now-30d TO now]",
            "size": 5,
            "fields": ["*"],
        }
    )
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    total = result["data"]["total"]
    assert total >= 0
    print(f"\n  [search_lucene date] total: {total}")


# ── audit_software (v4 API — different response shape) ────────────────────────


@pytest.mark.asyncio
async def test_audit_software(client):
    body = {
        "software": [
            {
                "part": "a",
                "vendor": "openssl",
                "product": "openssl",
                "version": "1.1.1u",
                "update": "*",
                "edition": "*",
                "language": "*",
                "platform": "*",
                "target_sw": "*",
                "target_hw": "*",
                "other": "*",
            }
        ],
        "match": "partial",
        "fields": [
            "title", "short_description", "description", "type",
            "href", "published", "modified", "ai_score", "cvelistMetrics",
        ],
    }
    result = await client.audit_software(body)
    assert isinstance(result, (dict, list))
    # v4 API returns {"result": [...]} with audit entries
    if isinstance(result, dict) and "result" in result:
        entries = result["result"]
        if isinstance(entries, list):
            assert len(entries) > 0
            entry = entries[0]
            assert "vulnerabilities" in entry
            vuln_count = len(entry["vulnerabilities"])
            assert vuln_count > 0
            print(f"\n  [audit_software] vulns for openssl 1.1.1u: {vuln_count}")
        else:
            # result == "OK" style
            assert result.get("result") == "OK"
            print(f"\n  [audit_software] OK response, keys: {list(result.keys())}")
    elif isinstance(result, list):
        assert len(result) > 0
        print(f"\n  [audit_software] entries: {len(result)}")


# ── get_supported_os ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_supported_os(client):
    result = await client.get_supported_os()
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    data = result["data"]
    # data should contain OS families
    assert len(data) > 0
    print(f"\n  [get_supported_os] OS families: {list(data.keys())[:5]}...")


# ── audit_linux_packages ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_linux_packages(client):
    body = {
        "os_name": "ubuntu",
        "os_version": "22.04",
        "packages": ["openssl 3.0.2 amd64"],
        "cvelist_metrics": True,
    }
    result = await client.audit_linux_packages(body)
    assert isinstance(result, dict)
    # v4 audit API may use different response shape
    if "result" in result:
        if result["result"] == "OK":
            data = result.get("data", {})
            print(f"\n  [audit_linux] data keys: {list(data.keys())}")
        elif isinstance(result["result"], list):
            print(f"\n  [audit_linux] entries: {len(result['result'])}")
        else:
            print(f"\n  [audit_linux] result: {result['result']}")
    else:
        print(f"\n  [audit_linux] keys: {list(result.keys())}")


# ── query_autocomplete ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_autocomplete(client):
    result = await client.query_autocomplete({"query": "log4j"})
    assert isinstance(result, dict)
    assert result.get("result") == "OK"
    data = result["data"]
    assert len(data) > 0
    print(f"\n  [autocomplete] suggestions: {len(data)}")


# ── search_cpe (v4 API) ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_cpe(client):
    result = await client.search_cpe(vendor="microsoft", product="windows_10", size=5)
    assert isinstance(result, dict)
    # v4 API may have different shape
    if "result" in result:
        if result["result"] == "OK":
            data = result.get("data", {})
            print(f"\n  [search_cpe] data keys: {list(data.keys())}")
        elif isinstance(result["result"], list):
            print(f"\n  [search_cpe] entries: {len(result['result'])}")
        else:
            print(f"\n  [search_cpe] result type: {type(result['result'])}")
    else:
        # Might return direct data
        assert len(result) > 0
        print(f"\n  [search_cpe] keys: {list(result.keys())}")
