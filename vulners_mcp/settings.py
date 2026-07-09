from __future__ import annotations

import logging
import os

from fastmcp.server.server import Transport
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# ``VULNERS_API_KEY`` used to configure a server-side fallback API key that
# every caller's request silently fell back to. That fallback was removed
# (see VU-1850 "client hardening"): a shared key baked into a *hosted*
# deployment let every anonymous caller burn the same Vulners quota and made
# per-caller auditing impossible.
#
# The env var itself is reintroduced here (VU-1850 "auth gate" MR) with a
# narrower meaning: it is the local operator's own key, used ONLY by the
# stdio transport (Claude Desktop / a locally-run server), where there is no
# per-request HTTP header to carry a caller's key. On the HTTP transport it
# is never consulted for a *caller's own* request -- see
# ``server._forward_headers`` and ``auth.AuthMiddleware``, both of which key
# off the live request via ``http_context.is_http_request()``, not this
# setting.
#
# ``VULNERS_MCP_ANON_API_KEY`` (VU-1850 "anonymous tier" MR) is the HTTP
# transport's equivalent for a caller who sends no key at all. Since VU-1850
# "discovery truth" it is no longer a second env var a hosted deployment
# *must* set to offer that tier: ``anon_api_key`` below falls back to
# ``VULNERS_API_KEY`` when ``VULNERS_MCP_ANON_API_KEY`` is unset, so an
# existing deployment's operator key keeps working, unchanged, as the
# anonymous tier's key -- no env change required. Set
# ``VULNERS_MCP_ANON_API_KEY`` explicitly only to back the anonymous tier
# with a *separate*, dedicated key instead of reusing the operator one; it
# always takes precedence over the ``VULNERS_API_KEY`` fallback when set.
# Whichever key ends up backing the tier, it is still: (a) subject to a size
# clamp and an app-level rate limit (see ``anon_max_size`` /
# ``mcp_rate_limit_rps`` below), and (b) never substituted for a caller key
# that Vulners itself rejected -- see ``auth.resolve_effective_auth``.
_API_KEY_ENV_VAR = "VULNERS_API_KEY"
_ANON_API_KEY_ENV_VAR = "VULNERS_MCP_ANON_API_KEY"
_TRANSPORT_MODE_ENV_VAR = "MCP_TRANSPORT_MODE"


class Settings(BaseSettings):
    mcp_transport_mode: Transport = "stdio"
    vulners_base_url: str = "https://vulners.com"

    # HTTP timeouts for calls to the Vulners API.
    # Env overrides: VULNERS_CONNECT_TIMEOUT_SECONDS / VULNERS_READ_TIMEOUT_SECONDS.
    vulners_connect_timeout_seconds: float = 5.0
    vulners_read_timeout_seconds: float = 30.0

    # Stateless Streamable HTTP: every request gets its own transport, with
    # no server-side session continuity required between calls. This lets
    # the hosted server (mcp.vulners.com) scale horizontally behind a load
    # balancer with no sticky routing. Env override: MCP_STATELESS_HTTP.
    mcp_stateless_http: bool = True

    # Anonymous-tier-only rate limit (see ``auth.AuthMiddleware``): a token
    # bucket cap applied ONLY to calls made on the shared ``anon_api_key``
    # (no caller-supplied ``X-Api-Key``). A caller who sends their own key is
    # never capped at this app layer -- real per-key/per-IP throttling for
    # keyed traffic is Vulners' and the Cloudflare edge's job, not ours.
    # Deliberately generous and global (not per-IP): this is an
    # abuse-of-last-resort belt protecting the shared anonymous-tier key's
    # quota from being burned by any single caller. Reused, not renamed,
    # from the pre-anonymous-tier "hard no-key mode" global limiter -- same
    # env var, narrower scope. Env override: MCP_RATE_LIMIT_RPS.
    mcp_rate_limit_rps: float = 30.0

    # The local operator's own Vulners API key, read from VULNERS_API_KEY.
    # See the module docstring above for the stdio-only usage contract. Also
    # the fallback source for ``anon_api_key`` below when
    # VULNERS_MCP_ANON_API_KEY is unset.
    stdio_api_key: str | None = Field(default=None, validation_alias=_API_KEY_ENV_VAR)

    # The Vulners API key backing the anonymous tier on the HTTP transport: a
    # caller who sends no ``X-Api-Key`` header still gets their
    # ``tools/call`` forwarded upstream, on THIS key -- subject to the size
    # clamp (``anon_max_size``) and rate limit (``mcp_rate_limit_rps``)
    # above.
    #
    # Resolved from, in order: VULNERS_MCP_ANON_API_KEY if set, else
    # VULNERS_API_KEY (the stdio operator key, reused) -- see the module
    # docstring above for why. Empty (neither env var set) means this
    # deployment offers no anonymous tier at all, and ``auth.AuthMiddleware``
    # falls back to the old hard-gate ``NO_API_KEY_MESSAGE``.
    anon_api_key: str = Field(
        default="",
        validation_alias=AliasChoices(_ANON_API_KEY_ENV_VAR, _API_KEY_ENV_VAR),
    )

    # Anonymous-tier-only argument clamp: any top-level integer ``size``
    # tool argument is clamped down to this value before the call reaches
    # Vulners, when the call is running on ``anon_api_key`` (see
    # ``auth.clamp_anon_args``). Keyed calls (the caller's own X-Api-Key)
    # are never clamped.
    anon_max_size: int = 10


def log_anon_tier_key_source() -> None:
    """Log, at INFO, when the anonymous tier is running on the fallback key.

    Fires only outside of stdio mode, and only when ``anon_api_key``'s
    fallback (see its ``validation_alias`` above) is the thing actually
    supplying the key: ``VULNERS_API_KEY`` is set and
    ``VULNERS_MCP_ANON_API_KEY`` is not. This replaces the old "VULNERS_API_KEY
    is ignored outside stdio" warning -- that claim is no longer true now
    that the anonymous tier reuses it. Neither env var's *value* is logged.

    Reads ``os.environ`` directly (mirroring ``Settings``' own env lookups)
    rather than the already-constructed ``settings`` singleton, so this stays
    accurately testable via ``monkeypatch.setenv`` independent of import
    order.
    """
    transport_mode = os.environ.get(_TRANSPORT_MODE_ENV_VAR, "stdio").lower()
    if (
        transport_mode != "stdio"
        and os.environ.get(_API_KEY_ENV_VAR)
        and not os.environ.get(_ANON_API_KEY_ENV_VAR)
    ):
        logger.info(
            "anonymous tier uses %s (set %s to use a separate key)",
            _API_KEY_ENV_VAR,
            _ANON_API_KEY_ENV_VAR,
        )


settings = Settings()
log_anon_tier_key_source()
