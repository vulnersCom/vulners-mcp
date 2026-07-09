# vulners_mcp/asgi.py
"""ASGI composition root for the HTTP transport.

This is what ``uvicorn`` actually serves for the hosted server (see
``vulners_mcp.__init__.main``) -- the previous version of this module was
broken and was deleted; this rebuilds it deliberately as a small composition
factory with an ``extra_routes`` seam so unrelated route groups can be
mounted alongside MCP, each without reaching into the other's app object.

Route ownership (keep this list in sync as routes are added):
  - MCP owns "/mcp" (the Streamable HTTP JSON-RPC endpoint), "/health", "/"
    (the mcp.html landing page), and any future discovery documents
    registered as ``@mcp.custom_route(...)`` on the FastMCP instance in
    ``server.py``. All of these are served by ``mcp_app`` below.
  - ``extra_routes`` is the seam for anything mounted alongside MCP without
    touching ``mcp_app`` or ``server.py``. Nothing uses it at present.
"""

from __future__ import annotations

from typing import Sequence

from fastmcp.server.http import StarletteWithLifespan
from starlette.applications import Starlette
from starlette.routing import BaseRoute, Mount

from .logging_utils import configure_logging

# Also configure logging here (not just in vulners_mcp.__init__.main()) so a
# bare `uvicorn vulners_mcp.asgi:app` -- bypassing main() entirely -- still
# logs. In practice vulners_mcp/__init__.py (imported first, as this
# module's parent package) already configured it; this call is then a cheap
# idempotent no-op, not a second configuration.
configure_logging()

from .server import mcp  # noqa: E402  (local: logging must be configured first, see above)
from .settings import settings  # noqa: E402

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
    the seam for injecting additional routes without modifying this module
    or ``server.py``.

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
