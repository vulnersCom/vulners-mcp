"""Tool-level contract tests for the VU-1850/VU-1946 hotfix.

Two things are covered here, both against REAL recorded Vulners API response
fixtures (``tests/fixtures/*.json``, captured with a live trial key -- see
the MR description for provenance), replayed through respx:

1. Integration-level regression guard for the v3/v4 envelope bug fixed in
   ``VulnersClient._unwrap`` (unit-level guard lives in ``test_envelope.py``):
   all 7 tools must succeed end-to-end, including the 3 that were previously
   dead in prod (``audit_linux_packages``, ``audit_software``, ``search_cpe``)
   because every v4 response was misread as a rejected request.
2. ``bulletin_by_id`` and ``search_lucene`` must request a curated field
   projection by default instead of unconditionally requesting
   ``fields=["*"]`` (and, for a single-ID ``bulletin_by_id`` call,
   ``references=true``). The old unconditional request could inflate a
   single bulletin from ~100 KiB to 113+ MiB for a heavily-referenced CVE
   (e.g. CVE-2021-44228 / Log4Shell) -- large enough to break real MCP
   client sessions.
"""

from __future__ import annotations

import json

import httpx

from vulners_mcp.server import DEFAULT_BULLETIN_FIELDS, DEFAULT_LUCENE_FIELDS, MAX_LUCENE_SIZE


# -------------------- All 7 tools succeed against real fixtures --------------------


async def test_bulletin_by_id_succeeds_with_real_v3_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2026-3909"})

    assert result.data["documents"]["CVE-2026-3909"]["id"] == "CVE-2026-3909"


async def test_search_lucene_succeeds_with_real_v3_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_lucene_v3.json")
    vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool("search_lucene", {"query": "type:cve"})

    assert result.data["total"] >= 1
    assert result.data["search"][0]["_source"]["id"]


async def test_get_supported_os_succeeds_with_real_v3_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("get_supported_os_v3.json")
    vulners_api.get("/api/v3/audit/getSupportedOS").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool("get_supported_os", {})

    assert "ubuntu" in result.data["supportedOS"]


async def test_query_autocomplete_succeeds_with_real_v3_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("query_autocomplete_v3.json")
    vulners_api.post("/api/v3/search/autocomplete").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool(
        "query_autocomplete", {"body": {"query": "log4j"}}
    )

    assert len(result.data["suggestions"]) > 0


async def test_audit_linux_packages_succeeds_with_real_v4_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Regression guard: this tool was DEAD in prod before the envelope fix
    (every call raised ApiError('Vulners API rejected the request')) because
    /api/v4/audit/linux's real response shape (``{"result": {...}}``, no
    ``"OK"``) didn't match what ``_unwrap`` recognized as success.
    """
    fixture = load_fixture("audit_linux_v4.json")
    vulners_api.post("/api/v4/audit/linux").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool(
        "audit_linux_packages",
        {"os": "ubuntu", "version": "22.04", "package": ["openssl 3.0.2 amd64"]},
    )

    assert result.data["totalPackages"] == 1
    assert result.data["issues"][0]["package"] == "openssl 3.0.2 amd64"


async def test_audit_software_succeeds_with_real_v4_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Regression guard: this tool was DEAD in prod before the envelope fix
    (see ``test_audit_linux_packages_succeeds_with_real_v4_fixture``) --
    ``/api/v4/audit/software``'s real response is ``{"result": [...]}``, a
    bare list, which ``_unwrap`` used to reject outright.
    """
    fixture = load_fixture("audit_software_v4.json")
    vulners_api.post("/api/v4/audit/software").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool(
        "audit_software",
        {
            "body": {
                "software": [
                    {
                        "part": "a",
                        "vendor": "openssl",
                        "product": "openssl",
                        "version": "1.0.1g",
                    }
                ]
            }
        },
    )

    # List-shaped payload: no output schema is declared (see
    # FORMERLY_MISDECLARED_TOOLS in test_envelope.py), so it rides as
    # unstructured content rather than result.data/structured_content --
    # same as the pre-existing search_lucene array-payload case.
    assert result.is_error is False
    parsed = json.loads(result.content[0].text)
    assert isinstance(parsed, list)
    assert parsed[0]["input"]["vendor"] == "openssl"
    assert len(parsed[0]["vulnerabilities"]) > 0


async def test_search_cpe_succeeds_with_real_v4_fixture(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Regression guard: this tool was DEAD in prod before the envelope fix
    (see the other v4 tests above) -- ``/api/v4/search/cpe``'s real response
    is ``{"result": {"best_match": ..., "cpe": [...]}}``, a dict, which
    ``_unwrap`` used to reject outright.
    """
    fixture = load_fixture("search_cpe_v4.json")
    vulners_api.get("/api/v4/search/cpe").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool(
        "search_cpe", {"vendor": "openssl", "product": "openssl"}
    )

    assert result.data["best_match"] == fixture["result"]["best_match"]
    assert len(result.data["cpe"]) > 0


# -------------------- bulletin_by_id: projection + references --------------------


async def test_bulletin_by_id_single_default_body_no_references_curated_fields(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2026-3909"})

    sent = json.loads(route.calls[0].request.content)
    assert sent["id"] == "CVE-2026-3909"
    assert sent["references"] is False
    assert sent["fields"] != ["*"]
    assert set(sent["fields"]) == set(DEFAULT_BULLETIN_FIELDS)


async def test_bulletin_by_id_single_references_is_opt_in(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool(
        "bulletin_by_id", {"id": "CVE-2026-3909", "references": True}
    )

    sent = json.loads(route.calls[0].request.content)
    assert sent["references"] is True


async def test_bulletin_by_id_fields_override_widens_projection(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2026-3909", "fields": ["*"]})

    sent = json.loads(route.calls[0].request.content)
    assert sent["fields"] == ["*"]


async def test_bulletin_by_id_list_always_forces_references_false_with_curated_fields(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool(
        "bulletin_by_id",
        {"id": ["CVE-2026-3909", "CVE-2024-0001"], "references": True},
    )

    sent = json.loads(route.calls[0].request.content)
    # `references=True` is ignored for list input -- always forced False.
    assert sent["references"] is False
    assert set(sent["fields"]) == set(DEFAULT_BULLETIN_FIELDS)


async def test_bulletin_by_id_projection_returns_curated_fields_for_real_log4shell_cve(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Real recorded proof of the size fix: CVE-2021-44228 (Log4Shell) is
    118,672,184 bytes with the old unconditional ``fields=["*"],
    references=true`` request, and 100,544 bytes (~1180x smaller) with the
    new curated default projection -- see
    ``tests/fixtures/bulletin_by_id_projected_log4j.json``, captured live
    against the real Vulners API using the new default request body.
    """
    fixture = load_fixture("bulletin_by_id_projected_log4j.json")
    vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2021-44228"})

    doc = result.data["documents"]["CVE-2021-44228"]
    for key in ("id", "title", "type", "cvss", "cvss3", "epss", "published", "enchantments"):
        assert key in doc
    # References weren't requested, so the reference graph must not be present.
    assert "references" not in doc


# -------------------- bulletin_by_id: VU-1946 leaner default --------------------
#
# mcp-!9 cut the default from ~113 MiB to ~98 KiB, but live testing showed even
# ~98 KiB can trip the Claude Code CLI's ~25k-token per-tool-result cap on the
# first (unnarrowed) call. Root cause (see verify/bulletin-fields-sizes.txt):
# 98.1% of that ~98 KiB was a single field, `enchantments`, and 88.9% of
# *that* was `enchantments.dependencies` / `.backreferences` (unbounded
# cross-reference indexes that scale with how much the wider ecosystem has
# written about a CVE) plus raw `.twitter` / `.reddit` mention dumps. The AI
# exploitation signal actually worth keeping by default -- `.exploitation`,
# `.score`, `.vulnersScore`, `.tags`, `.short_description` -- is only ~1.4%
# of `enchantments`. The Vulners API supports ES-style dot-path field
# projection into nested objects, so those sub-fields can be requested
# individually instead of the whole `enchantments` blob.


def test_default_bulletin_fields_excludes_heavy_fields() -> None:
    """The leaner default must drop `description` entirely, must not request
    the bare legacy `cvss` or `cvss2` variants (cvss3 only), and must not
    request the whole `enchantments` blob (only its compact sub-fields).
    """
    assert "description" not in DEFAULT_BULLETIN_FIELDS
    assert "cvss" not in DEFAULT_BULLETIN_FIELDS
    assert "cvss2" not in DEFAULT_BULLETIN_FIELDS
    assert "enchantments" not in DEFAULT_BULLETIN_FIELDS
    for heavy in (
        "enchantments.dependencies",
        "enchantments.backreferences",
        "enchantments.twitter",
        "enchantments.reddit",
    ):
        assert heavy not in DEFAULT_BULLETIN_FIELDS


def test_default_bulletin_fields_includes_lean_triage_set() -> None:
    """The leaner default must still cover a useful at-a-glance triage card."""
    for lean in (
        "id",
        "title",
        "type",
        "href",
        "published",
        "modified",
        "cvss3",
        "epss",
        "cvelist",
        "enchantments.exploitation",
        "enchantments.score",
    ):
        assert lean in DEFAULT_BULLETIN_FIELDS


async def test_bulletin_by_id_default_request_body_matches_lean_field_set(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2026-3909"})

    sent = json.loads(route.calls[0].request.content)
    assert "description" not in sent["fields"]
    assert "cvss" not in sent["fields"]
    assert "cvss2" not in sent["fields"]
    assert "enchantments" not in sent["fields"]
    assert "enchantments.exploitation" in sent["fields"]


async def test_bulletin_by_id_lean_default_projection_stays_under_byte_budget(
    mcp_client, vulners_api, load_fixture
) -> None:
    """Real recorded proof of the VU-1946 follow-up size fix: CVE-2021-44228
    (Log4Shell) is 100,544 bytes (~98 KiB) with the mcp-!9 curated default,
    and 2,230 bytes (~2.2 KiB, ~45x smaller) with the new leaner default --
    see ``tests/fixtures/bulletin_by_id_lean_log4j.json``, captured live
    against the real Vulners API with the new default field set (dot-path
    projection into `enchantments`), and
    ``verify/bulletin-fields-sizes.txt`` for the full per-field breakdown.

    Budget is set well above the real 2,174-byte document size (real number
    + generous headroom) so the test guards against a regression that
    reintroduces a heavy field (e.g. `enchantments.dependencies`) rather than
    pinning an exact byte count.
    """
    fixture = load_fixture("bulletin_by_id_lean_log4j.json")
    vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    result = await mcp_client.call_tool("bulletin_by_id", {"id": "CVE-2021-44228"})

    doc = result.data["documents"]["CVE-2021-44228"]
    for key in ("id", "title", "type", "cvss3", "epss", "cvelist", "enchantments"):
        assert key in doc
    assert "description" not in doc
    assert "cvss" not in doc
    assert "cvss2" not in doc
    assert "references" not in doc

    ench = doc["enchantments"]
    for key in ("exploitation", "score", "vulnersScore", "tags", "short_description"):
        assert key in ench
    for heavy in ("dependencies", "backreferences", "twitter", "reddit"):
        assert heavy not in ench

    assert len(json.dumps(doc, separators=(",", ":")).encode("utf-8")) < 10 * 1024


async def test_bulletin_by_id_fields_override_still_widens_past_lean_default(
    mcp_client, vulners_api, load_fixture
) -> None:
    """A caller who explicitly asks for `description` (or any other opt-in
    field not in the leaner default) must get exactly what they asked for --
    only the DEFAULT changed, the override mechanism from mcp-!9 is
    untouched.
    """
    fixture = load_fixture("search_id_v3.json")
    route = vulners_api.post("/api/v3/search/id").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool(
        "bulletin_by_id", {"id": "CVE-2026-3909", "fields": ["id", "title", "description"]}
    )

    sent = json.loads(route.calls[0].request.content)
    assert sent["fields"] == ["id", "title", "description"]


# -------------------- search_lucene: projection + size cap --------------------


async def test_search_lucene_default_body_has_curated_projection(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_lucene_v3.json")
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("search_lucene", {"query": "type:cve"})

    sent = json.loads(route.calls[0].request.content)
    assert sent["fields"] != ["*"]
    assert set(sent["fields"]) == set(DEFAULT_LUCENE_FIELDS)
    assert sent["size"] == 20


async def test_search_lucene_fields_override_widens_projection(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_lucene_v3.json")
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("search_lucene", {"query": "type:cve", "fields": ["*"]})

    sent = json.loads(route.calls[0].request.content)
    assert sent["fields"] == ["*"]


async def test_search_lucene_size_hard_capped_regardless_of_caller_request(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_lucene_v3.json")
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("search_lucene", {"query": "type:cve", "size": 5000})

    sent = json.loads(route.calls[0].request.content)
    assert sent["size"] == MAX_LUCENE_SIZE == 100


async def test_search_lucene_size_under_cap_is_untouched(
    mcp_client, vulners_api, load_fixture
) -> None:
    fixture = load_fixture("search_lucene_v3.json")
    route = vulners_api.post("/api/v3/search/lucene").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    await mcp_client.call_tool("search_lucene", {"query": "type:cve", "size": 42})

    sent = json.loads(route.calls[0].request.content)
    assert sent["size"] == 42
