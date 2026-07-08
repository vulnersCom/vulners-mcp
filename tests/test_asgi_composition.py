"""Tests for the ASGI composition factory (VU-1850 "auth gate" MR).

``vulners_mcp.asgi.build_asgi_app`` is the seam a parallel A2A MR will use to
mount its own routes (``/a2a``, ``/.well-known/agent-card.json``) alongside
MCP without touching ``server.py``. Two things must hold for that to work:

1. ``extra_routes`` are matched before the catch-all ``Mount("/", app=mcp_app)``.
2. The composed app reuses ``mcp_app.lifespan`` -- dropping this is exactly
   what breaks streamable-http with "task group was not initialized",
   because the Streamable HTTP session manager's task group is started by
   that lifespan, not by Starlette's default no-op one.

Note on fixtures: ``StreamableHTTPSessionManager.run()`` (invoked by a
FastMCP http_app's lifespan) can only be entered once per instance. The
module-level ``vulners_mcp.asgi.mcp_app`` / ``app`` singletons therefore may
only have their lifespan entered ONCE across this whole test session --
that budget is spent by ``test_default_app_serves_mcp_endpoint_with_lifespan_running``
below. Every other test that needs to actually run a request builds its own
fresh app via ``build_asgi_app(target_app=...)``.
"""

from __future__ import annotations

import json

from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from vulners_mcp.asgi import app as default_app
from vulners_mcp.asgi import build_asgi_app, mcp_app
from vulners_mcp.server import mcp
from vulners_mcp.settings import settings


async def _dummy_a2a_route(request):
    return PlainTextResponse("a2a placeholder")


def test_default_app_serves_mcp_endpoint_with_lifespan_running() -> None:
    """The module-level ``app`` (no extra routes) still answers /mcp -- this
    only works if the parent Starlette app actually ran mcp_app's lifespan
    (session manager task group startup); without it this request would
    raise "task group was not initialized" instead of returning 200.
    """
    with TestClient(default_app) as client:
        resp = client.post(
            "/mcp/",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "0"},
                    },
                }
            ),
        )
    assert resp.status_code == 200


def test_extra_routes_are_matched_before_the_mcp_catch_all_mount() -> None:
    fresh_mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    composed = build_asgi_app(
        extra_routes=[Route("/a2a", _dummy_a2a_route)], target_app=fresh_mcp_app
    )

    with TestClient(composed) as client:
        a2a_resp = client.get("/a2a")
        assert a2a_resp.status_code == 200
        assert a2a_resp.text == "a2a placeholder"

        # MCP's own routes are still reachable through the same composed app.
        health_resp = client.get("/health")
        assert health_resp.status_code == 200


def test_build_asgi_app_with_no_extra_routes_still_serves_health() -> None:
    fresh_mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    composed = build_asgi_app(target_app=fresh_mcp_app)
    with TestClient(composed) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "OK"


def test_composed_app_reuses_target_app_lifespan_object() -> None:
    """Guards the "lifespan propagation is CRITICAL" contract directly: the
    parent app's lifespan must literally be the mounted app's lifespan, not
    a fresh/default one. Pure attribute check -- no lifespan is entered, so
    this doesn't touch the "run once" budget.
    """
    composed = build_asgi_app()
    assert composed.router.lifespan_context is mcp_app.lifespan

    fresh_mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)
    composed_fresh = build_asgi_app(target_app=fresh_mcp_app)
    assert composed_fresh.router.lifespan_context is fresh_mcp_app.lifespan
