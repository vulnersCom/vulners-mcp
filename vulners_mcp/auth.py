# vulners_mcp/auth.py
"""HTTP auth gate: refuse anonymous ``tools/call`` on the public server.

Product decision (VU-1850): the hosted server (mcp.vulners.com, Streamable
HTTP) never spends a Vulners API key on behalf of an anonymous caller.
``initialize`` and ``tools/list`` stay open for discovery -- an agent must be
able to see what this server offers before it has a key. But a ``tools/call``
without an inbound ``X-Api-Key`` header used to be forwarded upstream anyway
(``VulnersClient`` never injects a fallback key -- see the VU-1850
client-hardening MR), which meant Vulners itself rejected it, and its
Cloudflare edge returned a raw bot-challenge HTML blob straight to the
calling agent. This middleware fails fast instead, with a clear, structured,
actionable error.
"""

from __future__ import annotations

from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .http_context import is_http_request

# Uniform across all 7 tools -- simple and honest. Kept as a single format so
# a test can assert on it verbatim without duplicating the copy.
NO_API_KEY_MESSAGE = (
    "This server does not hold API keys. Send your personal Vulners API key "
    "in the X-Api-Key HTTP header. Get a key: sign in at "
    "https://vulners.com/userinfo (human, in a browser). "
    "Details: https://mcp.vulners.com/auth.md"
)


def _has_api_key_header() -> bool:
    headers = get_http_headers(include_all=True) or {}
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    return bool(lower.get("x-api-key"))


class RequireApiKeyMiddleware(Middleware):
    """Reject anonymous ``tools/call`` over HTTP; leave everything else alone.

    - Only ``on_call_tool`` is overridden, so ``initialize``, ``tools/list``,
      ``resources/*`` and ``prompts/*`` are never touched by this middleware
      -- FastMCP only dispatches to ``on_call_tool`` for the ``tools/call``
      method (see ``fastmcp.server.middleware.middleware.Middleware``).
    - stdio transport is untouched: ``is_http_request()`` is False whenever
      there is no live inbound HTTP request (i.e. always, in stdio mode), so
      the gate never fires there. The local/Claude-Desktop flow keeps using
      the owner's key from ``settings.stdio_api_key``.
    - An HTTP ``tools/call`` without an inbound ``X-Api-Key`` header raises a
      :class:`fastmcp.exceptions.ToolError` with a structured, actionable
      message *before* any upstream call is made -- nothing goes to Vulners
      for an anonymous caller.
    """

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        if is_http_request() and not _has_api_key_header():
            raise ToolError(NO_API_KEY_MESSAGE)
        return await call_next(context)
