from __future__ import annotations

import logging
import os

from fastmcp.server.server import Transport
from pydantic import Field
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
# is never consulted -- see ``server._forward_headers`` and
# ``auth.RequireApiKeyMiddleware``, both of which key off the live request
# via ``http_context.is_http_request()``, not this setting.
_API_KEY_ENV_VAR = "VULNERS_API_KEY"
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

    # Abuse-of-last-resort belt on the HTTP transport (see
    # ``server.mcp.add_middleware(RateLimitingMiddleware(...))``).
    # Deliberately generous and *global*, not per-caller/IP -- real per-IP
    # throttling belongs at the Cloudflare edge in front of mcp.vulners.com.
    # Env override: MCP_RATE_LIMIT_RPS.
    mcp_rate_limit_rps: float = 30.0

    # The local operator's own Vulners API key, read from VULNERS_API_KEY.
    # See the module docstring above for the stdio-only usage contract.
    stdio_api_key: str | None = Field(default=None, validation_alias=_API_KEY_ENV_VAR)


def warn_if_api_key_env_set_outside_stdio() -> None:
    """Log a warning if ``VULNERS_API_KEY`` is set while not in stdio mode.

    stdio legitimately uses this as the local operator's own key
    (``settings.stdio_api_key``). Outside of stdio it is never read -- every
    HTTP call must carry its own caller-supplied ``X-Api-Key`` header -- so a
    deployment that still sets this env var is silently wasting a key and
    should have it removed from its environment.

    Reads ``os.environ`` directly (mirroring ``Settings``' own env lookups)
    rather than the already-constructed ``settings`` singleton, so this stays
    accurately testable via ``monkeypatch.setenv`` independent of import
    order.
    """
    transport_mode = os.environ.get(_TRANSPORT_MODE_ENV_VAR, "stdio").lower()
    if transport_mode != "stdio" and os.environ.get(_API_KEY_ENV_VAR):
        logger.warning(
            "%s is set but ignored in %s transport mode; the hosted server "
            "never uses a server-side key — callers must send their own "
            "X-Api-Key header. Remove this variable from the deployment "
            "environment.",
            _API_KEY_ENV_VAR,
            transport_mode,
        )


settings = Settings()
warn_if_api_key_env_set_outside_stdio()
