# vulners_mcp/http_context.py
"""Shared helper for detecting whether the current call is running over HTTP.

Both the auth gate (:mod:`vulners_mcp.auth`) and per-request header
forwarding (:func:`vulners_mcp.server._forward_headers`) need the same
answer to "is there a live inbound HTTP request right now, or are we in
stdio mode".

stdio never has an HTTP request in flight, so :func:`is_http_request` is a
stronger and more robust signal than reading ``settings.mcp_transport_mode``:
that is a static, process-wide setting that a misconfigured deployment could
leave at its ``"stdio"`` default while the process is, in practice, wired up
behind uvicorn/ASGI (e.g. someone runs ``uvicorn vulners_mcp.asgi:app``
directly instead of going through ``vulners_mcp.main()``). Keying the auth
gate and the stdio-key fallback off the actual per-call request context means
both are correct regardless of how ``MCP_TRANSPORT_MODE`` was set.
"""

from __future__ import annotations

from fastmcp.server.dependencies import get_http_request


def is_http_request() -> bool:
    """Return True if a real inbound HTTP request is in flight for this call.

    Never raises: ``get_http_request()`` raises ``RuntimeError`` when there
    is no active HTTP request (stdio transport, or a call made outside of
    any request context, e.g. directly in a unit test), which we treat as
    "not HTTP".
    """
    try:
        get_http_request()
    except RuntimeError:
        return False
    return True
