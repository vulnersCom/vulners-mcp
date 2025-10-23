#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables from .env file in the script directory
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
else
    echo "Error: .env file not found in $SCRIPT_DIR"
    echo "Please create a .env file with your VULNERS_API_KEY"
    echo "Example: VULNERS_API_KEY=your_api_key_here"
    exit 1
fi

# Check if VULNERS_API_KEY is set
if [ -z "$VULNERS_API_KEY" ]; then
    echo "Error: VULNERS_API_KEY not found in .env file"
    exit 1
fi

# Run the Docker container in HTTP mode (detached)
docker run -d \
  --name vulners-mcp-http \
  -e MCP_TRANSPORT_MODE="http" \
  -e VULNERS_BASE_URL="https://vulners.com" \
  -e VULNERS_API_KEY="$VULNERS_API_KEY" \
  -p 8000:8000 \
  vulners-mcp:latest
