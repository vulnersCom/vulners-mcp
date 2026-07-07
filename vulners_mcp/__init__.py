from vulners_mcp._version import __version__
from vulners_mcp.server import mcp
from .settings import settings

__all__ = ["__version__", "main", "mcp", "settings"]


def main():
    mcp.run(transport=settings.mcp_transport_mode)


if __name__ == "__main__":
    main()
