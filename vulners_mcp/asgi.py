# vulners_mcp/asgi.py
"""ASGI composition root for the HTTP transport.

This is what ``uvicorn`` actually serves for the hosted server (see
``vulners_mcp.__init__.main``) -- the previous version of this module was
broken and was deleted; this rebuilds it deliberately as a small composition
factory so a sibling MR can mount unrelated route groups (A2A) alongside MCP
without either one reaching into the other's app object.

Route ownership (keep this list in sync as routes are added):
  - MCP owns "/mcp" (the Streamable HTTP JSON-RPC endpoint), "/health", "/"
    (the mcp.html landing page), and any future discovery documents
    registered as ``@mcp.custom_route(...)`` on the FastMCP instance in
    ``server.py``. All of these are served by ``mcp_app`` below.
  - A2A (a parallel MR) will own "/a2a" and
    "/.well-known/agent-card.json", injected via ``extra_routes`` below --
    it must NOT touch ``mcp_app`` or ``server.py``.
"""

from __future__ import annotations

from typing import Sequence

from fastmcp.server.http import StarletteWithLifespan
from starlette.applications import Starlette
from starlette.routing import BaseRoute, Mount

from .server import mcp
from .settings import settings

# The FastMCP Streamable HTTP app. A single object that carries the "/mcp"
# endpoint, every `@mcp.custom_route`, AND the streamable-http session
# manager's lifespan (its task group startup/shutdown). That lifespan is why
# `build_asgi_app` below MUST pass `lifespan=mcp_app.lifespan` to the parent
# Starlette app -- without it, streamable-http breaks at request time with
# "task group was not initialized".
#
# `stateless_http` is settings-driven (MCP_STATELESS_HTTP, default True): the
# hosted server treats every request as independent, with no server-side
# mcp-session-id continuity required, so it can scale horizontally behind a
# load balancer with no sticky routing.
mcp_app = mcp.http_app(path="/mcp", stateless_http=settings.mcp_stateless_http)


def build_asgi_app(
    extra_routes: Sequence[BaseRoute] | None = None,
    *,
    target_app: StarletteWithLifespan | None = None,
) -> Starlette:
    """Compose the top-level ASGI app.

    ``extra_routes`` are exact-path routes mounted BEFORE the catch-all
    ``Mount("/", app=mcp_app)``, so a route defined here always wins over
    anything ``mcp_app`` might otherwise answer for the same path. This is
    the seam a parallel A2A MR is expected to use to inject its own routes
    without modifying this module or ``server.py``.

    ``target_app`` overrides which FastMCP HTTP app gets mounted; it exists
    for tests. ``mcp_app`` above is a module-level singleton, and its
    Streamable HTTP session manager's lifespan can only ever be entered
    *once* per process (``StreamableHTTPSessionManager.run()`` raises on a
    second call) -- so a test suite that wants more than one independent
    end-to-end request through a composed app must build its own fresh
    ``mcp.http_app(...)`` and pass it here, rather than exhausting the real
    singleton that ``app`` (below) is built from.
    """
    mounted_app = target_app if target_app is not None else mcp_app
    routes: list[BaseRoute] = [*(extra_routes or []), Mount("/", app=mounted_app)]
    return Starlette(routes=routes, lifespan=mounted_app.lifespan)


app = build_asgi_app()
