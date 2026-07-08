"""Shared pytest fixtures for the vulners-mcp test suite.

Fixture names here are deliberately distinct from names that sibling test
modules define locally (e.g. ``tests/test_discovery_routes.py`` — added by a
different branch — defines its own module-scoped ``client`` fixture wrapping
``TestClient(mcp.http_app())``). Keeping names disjoint means both test
modules keep working unmodified once the branches are stacked on top of
each other.
"""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterator

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from starlette.testclient import TestClient

import vulners_mcp.server as server_module
from vulners_mcp.server import mcp
from vulners_mcp.settings import settings

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_rate_limiter_bucket() -> None:
    """Refill the global rate limiter's token bucket before every test.

    ``server_module.rate_limiter`` is attached once to the module-level,
    session-wide ``mcp`` object (see ``server.py``), so without this its
    token bucket would accumulate consumption across the whole test session
    and could spuriously trip "Global rate limit exceeded" in a test that
    has nothing to do with rate limiting. A dedicated behavioral test for
    the limiter itself lives in ``tests/test_rate_limit.py``.
    """
    bucket = server_module.rate_limiter.global_limiter
    bucket.tokens = bucket.capacity
    bucket.last_refill = time.time()


@pytest.fixture(autouse=True)
async def _reset_vulners_client_singleton() -> AsyncIterator[None]:
    """Reset the module-level ``VulnersClient`` singleton around every test.

    ``vulners_mcp.server`` lazily builds and caches a single shared
    ``VulnersClient`` (and the ``httpx.AsyncClient`` it wraps). Because
    pytest-asyncio gives each test function its own event loop, reusing a
    client created in a previous test's loop raises "Event loop is closed".
    Clearing the singleton before and after each test forces a fresh client
    bound to the current loop, and this also guarantees no test can
    accidentally reuse an httpx transport left over from another test.
    """
    server_module._client = None
    yield
    leftover = server_module._client
    server_module._client = None
    if leftover is not None:
        await leftover.close()


@pytest.fixture
async def mcp_client() -> AsyncIterator[Client]:
    """In-process MCP client wired directly to the ``FastMCP`` server object.

    ``fastmcp.Client`` drives the server's handlers in-process (no socket, no
    subprocess), exercising the same tool-dispatch code path a real MCP
    client would use over Streamable HTTP.
    """
    async with Client(mcp) as connected_client:
        yield connected_client


@pytest.fixture
def mcp_http_client() -> Iterator[TestClient]:
    """Starlette ``TestClient`` over ``mcp.http_app()``.

    Use this for asserting on the HTTP surface (custom routes, headers,
    status codes) rather than the MCP protocol itself.
    """
    with TestClient(mcp.http_app()) as test_client:
        yield test_client


@pytest.fixture
def vulners_api() -> Iterator[respx.MockRouter]:
    """Intercept every HTTP call made to the Vulners API base URL.

    Scoped to ``settings.vulners_base_url`` (``https://vulners.com`` by
    default) with ``assert_all_mocked=True``, so a test that forgets to mock
    a route it actually calls fails loudly instead of silently reaching out
    over the network.
    """
    with respx.mock(
        base_url=settings.vulners_base_url, assert_all_mocked=True
    ) as router:
        yield router


@pytest.fixture
def mcp_streamable_http_client_factory() -> Callable[..., Any]:
    """Factory for a real Streamable-HTTP-over-ASGI ``fastmcp.Client``.

    Unlike ``mcp_client`` (wired directly to the in-process ``FastMCP``
    object, which never goes through an HTTP request at all), this drives an
    actual request through ``mcp.http_app()`` via ``httpx.ASGITransport`` —
    no real socket, but genuine Starlette request/response handling. That
    matters because ``server._forward_headers`` reads headers via
    ``get_http_headers()``, which only returns anything when there is a real
    inbound HTTP request in flight. Use this fixture (over ``mcp_client``)
    for any test that asserts on header forwarding.
    """

    @asynccontextmanager
    async def _make(headers: dict[str, str] | None = None) -> AsyncIterator[Client]:
        app = mcp.http_app()

        def _httpx_client_factory(
            headers: dict[str, str] | None = None,
            auth: httpx.Auth | None = None,
            follow_redirects: bool = True,
            **kwargs: Any,
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
                headers=headers,
                follow_redirects=follow_redirects,
            )

        transport = StreamableHttpTransport(
            url="http://testserver/mcp",
            headers=headers,
            httpx_client_factory=_httpx_client_factory,
        )
        # ``mcp.http_app()`` needs its lifespan run (it starts the streamable
        # HTTP session manager's task group) — the same thing a parent ASGI
        # app or `starlette.testclient.TestClient` would normally do for us.
        async with app.router.lifespan_context(app):
            async with Client(transport) as connected_client:
                yield connected_client

    return _make


@pytest.fixture
def fixtures_dir() -> Path:
    """Directory holding static fixture payloads used to mock API responses."""
    return FIXTURES_DIR


@pytest.fixture
def load_fixture(fixtures_dir: Path) -> Callable[[str], Any]:
    """Return a loader that reads and JSON-decodes a file from ``tests/fixtures/``."""

    def _load(name: str) -> Any:
        return json.loads((fixtures_dir / name).read_text())

    return _load
