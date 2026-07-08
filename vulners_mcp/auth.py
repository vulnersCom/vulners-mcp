# vulners_mcp/auth.py
"""HTTP auth gate + anonymous tier resolution.

Product decision (VU-1850, "anonymous tier"): the hosted server
(mcp.vulners.com, Streamable HTTP) offers three tiers of access to a
``tools/call``:

1. A caller sends their own ``X-Api-Key`` header -- forwarded verbatim,
   uncapped at this layer (real per-key throttling is Vulners' own problem;
   the Cloudflare edge in front of mcp.vulners.com is the abuse belt).
2. A caller sends no key, and this deployment has a dedicated, low-privilege
   ``settings.anon_api_key`` configured -- the call is allowed to proceed on
   THAT key, with a size clamp (``settings.anon_max_size``) applied to any
   ``size``-style argument and a shared, app-level rate limit
   (``settings.mcp_rate_limit_rps``) protecting that key's quota from being
   burned by a single caller.
3. A caller sends no key, and no anonymous-tier key is configured -- graceful
   degradation to the old hard-gate behavior: a structured, actionable
   ``ToolError`` before anything is sent upstream.

``initialize`` and ``tools/list`` stay open for discovery in all cases -- an
agent must be able to see what this server offers before it has a key.
stdio transport is untouched: it never has a live HTTP request in flight
(see ``http_context.is_http_request``), so it always uses the local
operator's own key (``settings.stdio_api_key``), never the anonymous-tier
key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.rate_limiting import TokenBucketRateLimiter

from .http_context import is_http_request
from .settings import settings

# Shown only when a caller sends no key AND this deployment has no anonymous
# tier configured -- graceful degradation to the pre-anonymous-tier hard
# gate. Kept as a single format so a test can assert on it verbatim without
# duplicating the copy.
NO_API_KEY_MESSAGE = (
    "This server does not hold a privileged API key, and no anonymous tier "
    "is configured on this deployment. Send your personal Vulners API key "
    "in the X-Api-Key HTTP header. Get a key: sign in at "
    "https://vulners.com/userinfo (human, in a browser). "
    "Details: https://mcp.vulners.com/auth.md "
    "(When configured, this server's anonymous tier is itself size- and "
    "rate-limited -- your own key always gets full limits.)"
)

# Shown for an anonymous-tier call (no caller key, anon key configured) once
# its quota/rate budget is exhausted -- whether that's this server's own
# app-level limiter (see AuthMiddleware.rate_limiter) or Vulners itself
# returning 429 for the anon key (see vulners_client._sanitize_message).
# Reused verbatim in both places so the guidance a caller sees is identical
# either way.
ANON_TIER_LIMIT_MESSAGE = (
    "Anonymous tier quota/rate reached — send your own X-Api-Key for full "
    "limits, see https://mcp.vulners.com/auth.md"
)


def _caller_api_key() -> str | None:
    """Return the caller-supplied ``X-Api-Key`` header, if any, stripped."""
    headers = get_http_headers(include_all=True) or {}
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    value = lower.get("x-api-key")
    return value.strip() if value else None


@dataclass(frozen=True)
class EffectiveAuth:
    """The resolved outbound auth for one call.

    ``headers`` is exactly what ``VulnersClient`` should be given (``None``
    means "send no auth header at all"). ``mode`` records *why*, both for
    the anon-tier clamp/rate-limit decision (``is_anon``) and for readable
    test assertions:

    - ``"keyed"``   -- the caller's own header, forwarded verbatim.
    - ``"stdio"``   -- the stdio operator's own key (``VULNERS_API_KEY``).
    - ``"anon-tier"`` -- no caller key; this deployment's dedicated
      low-privilege anonymous-tier key.
    - ``"none"``    -- HTTP transport, no caller key, no anon tier
      configured. ``AuthMiddleware`` raises ``NO_API_KEY_MESSAGE`` for
      exactly this mode, before ``call_next`` runs -- nothing reaches
      ``VulnersClient``.
    - ``"stdio-no-key"`` -- stdio transport with no owner key configured
      either. A legitimate, if unusual, terminal state: unlike ``"none"``
      it is never gated (stdio has no anonymous tier to fall back to, and
      was never gated by ``AuthMiddleware`` in the first place -- see its
      docstring). Kept distinct from ``"none"`` specifically so the
      middleware's single ``mode == "none"`` check can never accidentally
      gate stdio.
    """

    headers: dict[str, str] | None
    mode: str

    @property
    def is_anon(self) -> bool:
        return self.mode == "anon-tier"


def resolve_effective_auth() -> EffectiveAuth:
    """Resolve the effective outbound auth for the current call.

    Precedence, checked in order:

    1. The caller's own ``X-Api-Key`` header (HTTP transport only -- there is
       no per-request header at all in stdio mode).
    2. stdio transport's local operator key (``settings.stdio_api_key``),
       only when there is no live HTTP request in flight.
    3. HTTP transport's anonymous-tier key (``settings.anon_api_key``), only
       when configured.
    4. No key at all.

    This is the single source of truth for "what key does this call use, and
    why" -- both ``AuthMiddleware`` (the gate + anon clamp/rate-limit) and
    ``server._forward_headers`` (what actually gets sent to Vulners) call
    into this function rather than re-deriving the answer independently, so
    the two can never disagree.
    """
    caller_key = _caller_api_key()
    if caller_key:
        return EffectiveAuth(headers={"X-Api-Key": caller_key}, mode="keyed")

    if not is_http_request():
        if settings.stdio_api_key:
            return EffectiveAuth(
                headers={"X-Api-Key": settings.stdio_api_key}, mode="stdio"
            )
        return EffectiveAuth(headers=None, mode="stdio-no-key")

    if settings.anon_api_key:
        return EffectiveAuth(
            headers={"X-Api-Key": settings.anon_api_key}, mode="anon-tier"
        )

    return EffectiveAuth(headers=None, mode="none")


def clamp_anon_args(arguments: dict[str, Any] | None) -> dict[str, Any] | None:
    """Clamp a top-level integer ``size`` tool argument for the anon tier.

    Deliberately generic rather than tool-specific: several tools accept a
    ``size``-style result-count argument (``search_lucene``, ``search_cpe``);
    rather than special-case each tool name, clamp any top-level argument
    literally named ``size`` down to ``settings.anon_max_size`` when it is an
    int larger than that. A ``size`` argument the caller never sent at all is
    left alone (falls through to that tool's own default) -- this is a
    deliberate simplification, not a hard cap; the real abuse belt for the
    anonymous tier is the app-level rate limiter plus the Cloudflare edge,
    not perfect argument scrubbing.
    """
    if not arguments or "size" not in arguments:
        return arguments
    size = arguments["size"]
    if (
        isinstance(size, int)
        and not isinstance(size, bool)
        and size > settings.anon_max_size
    ):
        arguments = {**arguments, "size": settings.anon_max_size}
    return arguments


class AuthMiddleware(Middleware):
    """Gate + anonymous-tier policy for ``tools/call`` over HTTP.

    - Only ``on_call_tool`` is overridden, so ``initialize``, ``tools/list``,
      ``resources/*`` and ``prompts/*`` are never touched -- FastMCP only
      dispatches to ``on_call_tool`` for the ``tools/call`` method (see
      ``fastmcp.server.middleware.middleware.Middleware``).
    - stdio transport is untouched: ``resolve_effective_auth()`` only ever
      returns ``"stdio"`` or ``"stdio-no-key"`` when there is no live HTTP
      request, and this middleware only rejects/rate-limits/clamps for
      ``"none"`` and ``"anon-tier"`` (both HTTP-only by construction) --
      ``"stdio"`` and ``"stdio-no-key"`` always fall through untouched.
    - ``mode == "none"`` can only happen over HTTP (see
      ``EffectiveAuth.mode`` docstring) -- raises the guidance ``ToolError``
      before any upstream call is made.
    - ``mode == "anon-tier"``: consumes one token from the shared, app-level
      rate limiter (rejecting with ``ANON_TIER_LIMIT_MESSAGE`` if empty) and
      clamps ``size``-style arguments, then proceeds on the anon key.
    - ``mode in ("keyed", "stdio")``: passes through untouched -- no clamp,
      no app-level rate limit.
    """

    def __init__(self, *, rate_limiter: TokenBucketRateLimiter | None = None) -> None:
        # Token bucket sized off the same setting the anonymous tier has
        # always used (``settings.mcp_rate_limit_rps``) -- see that field's
        # docstring in ``settings.py`` for why this is anon-only, not global.
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter(
            capacity=max(1, int(settings.mcp_rate_limit_rps * 2)),
            refill_rate=settings.mcp_rate_limit_rps,
        )

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        auth = resolve_effective_auth()

        if auth.mode == "none":
            raise ToolError(NO_API_KEY_MESSAGE)

        if auth.is_anon:
            if not await self.rate_limiter.consume():
                raise ToolError(ANON_TIER_LIMIT_MESSAGE)
            context.message.arguments = clamp_anon_args(context.message.arguments)

        return await call_next(context)
