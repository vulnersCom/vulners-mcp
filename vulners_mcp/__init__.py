import os
from vulners_mcp.server import mcp


def main():
    # Check if HTTP mode is explicitly requested via environment variable
    transport_mode = os.getenv("MCP_TRANSPORT_MODE", "").lower()
    
    if transport_mode == "http":
        # Explicitly run HTTP server
        mcp.run(transport="http")
    else:
        # Default: let FastMCP auto-detect (stdio for Claude Desktop, HTTP otherwise)
        mcp.run()


if __name__ == "__main__":
    main()
