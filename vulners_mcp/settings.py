from __future__ import annotations

import logging
import os

from fastmcp.server.server import Transport
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# Legacy env var that used to configure a server-side fallback API key. The
# fallback was removed (see VU-1850 "client hardening"): a shared key baked
# into the deployment let every caller silently burn the same Vulners quota
# and made per-caller auditing impossible. It is intentionally *not* a field
# on ``Settings`` any more, so it is checked directly against the process
# environment purely to warn operators who still set it.
_LEGACY_API_KEY_ENV_VAR = "VULNERS_API_KEY"


class Settings(BaseSettings):
    mcp_transport_mode: Transport = "stdio"
    vulners_base_url: str = "https://vulners.com"

    # HTTP timeouts for calls to the Vulners API.
    # Env overrides: VULNERS_CONNECT_TIMEOUT_SECONDS / VULNERS_READ_TIMEOUT_SECONDS.
    vulners_connect_timeout_seconds: float = 5.0
    vulners_read_timeout_seconds: float = 30.0


def warn_if_legacy_api_key_env_set() -> None:
    """Log a warning if the removed ``VULNERS_API_KEY`` env var is still set.

    The variable is ignored: ``VulnersClient`` never injects a server-side key
    any more, so requests without a caller-supplied ``X-Api-Key`` go upstream
    with no key at all (Vulners rejects them itself).
    """
    if os.environ.get(_LEGACY_API_KEY_ENV_VAR):
        logger.warning(
            "%s is set but ignored; clients must send their own X-Api-Key "
            "header — this server no longer forwards a server-side fallback key.",
            _LEGACY_API_KEY_ENV_VAR,
        )


settings = Settings()
warn_if_legacy_api_key_env_set()
