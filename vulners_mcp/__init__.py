from vulners_mcp.logging_utils import configure_logging

# Configure logging before anything else is imported: importing
# vulners_mcp.server below pulls in vulners_mcp.auth -> vulners_mcp.settings,
# and settings.py fires its own startup INFO log (log_anon_tier_key_source())
# as a module-level side effect at import time -- i.e. before main() below
# ever runs. Doing this first, rather than only inside main(), is what makes
# that log line (and any other import-time logging) actually show up.
configure_logging()

import fastmcp  # noqa: E402  (local: logging must be configured first, see above)
import uvicorn  # noqa: E402

from vulners_mcp._version import __version__  # noqa: E402
from vulners_mcp.server import mcp  # noqa: E402
from .settings import settings  # noqa: E402

__all__ = ["__version__", "main", "mcp", "settings"]


def main():
    if settings.mcp_transport_mode == "stdio":
        # Claude Desktop / local flow: no HTTP at all, no ASGI composition.
        mcp.run(transport="stdio")
        return

    # Hosted flow: run the composed ASGI app (vulners_mcp.asgi:app) under
    # uvicorn directly, instead of FastMCP's own run_http_async(), so the
    # auth gate, stateless-HTTP setting, rate limiter, and (future) extra
    # routes mounted in asgi.py are actually in effect. Passed as an import
    # string so uvicorn imports "vulners_mcp.asgi" itself; host/port match
    # what mcp.run(transport="http") used before (fastmcp.settings, i.e. the
    # FASTMCP_HOST / FASTMCP_PORT env vars).
    configure_logging()  # no-op if already configured above; cheap safety net
    uvicorn.run(
        "vulners_mcp.asgi:app",
        host=fastmcp.settings.host,
        port=fastmcp.settings.port,
        log_level=fastmcp.settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
