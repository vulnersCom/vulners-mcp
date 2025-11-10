from vulners_mcp.server import mcp
from .settings import settings


def main():
    mcp.run(transport=settings.mcp_transport_mode)


if __name__ == "__main__":
    main()
