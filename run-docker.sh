#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Optionally load environment variables from a .env file in the script
# directory (e.g. to override VULNERS_BASE_URL). No API key is needed here:
# the HTTP server never spends a server-side key -- each caller sends their
# own Vulners API key in the X-Api-Key header on every request. See
# README.md "Authentication" for details.
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# Run the Docker container in HTTP mode (detached)
docker run -d \
  --name vulners-mcp-http \
  -e MCP_TRANSPORT_MODE="http" \
  -e VULNERS_BASE_URL="https://vulners.com" \
  -p 8000:8000 \
  vulners-mcp:latest
