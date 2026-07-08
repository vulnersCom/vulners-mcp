import fastmcp
import uvicorn

from vulners_mcp._version import __version__
from vulners_mcp.server import mcp
from .settings import settings

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
    uvicorn.run(
        "vulners_mcp.asgi:app",
        host=fastmcp.settings.host,
        port=fastmcp.settings.port,
        log_level=fastmcp.settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
