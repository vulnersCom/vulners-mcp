# Vulners MCP Server

**Vulners MCP** is a Model Context Protocol (MCP) server that provides seamless access to the Vulners vulnerability database through AI assistants like Claude Desktop. It enables security researchers and developers to query comprehensive vulnerability data, search for CVEs, analyze security bulletins, and audit software packages directly through natural language conversations.

## Features

- **AI Assistant Integration**: Works natively with Claude Desktop and other MCP-compatible clients
- **Dual Transport Support**: Automatically detects and supports both stdio (for Claude Desktop) and HTTP transports
- **Comprehensive Tools**: 7 MCP tools for vulnerability research including:
  - Full-text Lucene search across 4M+ vulnerability bulletins
  - CVE and bulletin information retrieval
  - Software/package vulnerability auditing
  - CPE search and autocomplete
  - Linux package vulnerability auditing
- **Flexible Deployment**: Docker, local build, or PyPI installation
- **Environment-based Configuration**: Simple setup via environment variables

## Table of Contents

- [Requirements](#requirements)  
- [Obtaining Vulners API Key](#obtaining-vulners-api-key)  
- [Quick Start with Claude Desktop](#quick-start-with-claude-desktop)  
- [Installation & Deployment](#installation--deployment)  
  - [Docker with run script](#docker-with-run-script)
  - [Docker (manual)](#docker-manual)  
  - [Build & run locally](#build--run-locally)  
- [Configuration / Environment Variables](#configuration--environment-variables)  
- [Usage & Endpoints](#usage--endpoints)  
- [Testing](#testing)
- [Available Tools](#available-tools)
- [Development & Contributing](#development--contributing)  
- [License](#license)

---

## Requirements

- Python 3.9+  
- Access to the Vulners API (valid API key and network connectivity)  
- (For Docker) Docker engine  

---

## Obtaining Vulners API Key

Please, register at [Vulners website](https://vulners.com).
Go to the personal menu by clicking at your name at the right top corner.
Follow "API KEYS" tab.
Generate API key with scope "api" and use it with the library.

---

## Quick Start with Claude Desktop

The easiest way to use Vulners MCP is through Claude Desktop:

### 1. Build the Docker Image

```bash
git clone https://github.com/vulnersCom/vulners-mcp.git
cd vulners-mcp
docker build -t vulners-mcp:latest .
```

### 2. Configure Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vulners": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "VULNERS_API_KEY=YOUR_API_KEY_HERE",
        "vulners-mcp:latest"
      ]
    }
  }
}
```

Replace `YOUR_API_KEY_HERE` with your actual Vulners API key.

### 3. Restart Claude Desktop

After saving the configuration, restart Claude Desktop. The Vulners MCP server will be available through the 🔌 icon.

### 4. Start Using

You can now ask Claude questions like:

- "Find recent vulnerabilities in Google Chrome"
- "Show me details for CVE-2025-53770"
- "What are recent exploted vulnerabilities in Citrix products"
- "Audit this software: cpe:2.3:a:google:chrome:138.0.7204.184:*:*:*:*:*:*:*"
- "Audit ubuntu 22.04 packages 'openssl 3.0.2 amd64' and 'curl 7.81.0-1ubuntu1.14 amd64'"

---

## Installation & Deployment

### Docker with run script

For easy HTTP mode deployment, use the provided run script:

```bash
# Create .env file with your API key
echo "VULNERS_API_KEY=your_api_key_here" > .env

# Run the server
./run-docker.sh
```

The server will start in HTTP mode at <http://0.0.0.0:8000/mcp>

### Docker (manual)

Run the MCP server in HTTP mode:

```bash
docker run -d \
  --name vulners-mcp-http \
  -e MCP_TRANSPORT_MODE="http" \
  -e VULNERS_BASE_URL="https://vulners.com" \
  -e VULNERS_API_KEY="your_api_key" \
  -p 8000:8000 \
  vulners-mcp:latest
```

For Claude Desktop (stdio mode), the `-i` flag is used instead:

```bash
docker run -i --rm \
  -e VULNERS_API_KEY="your_api_key" \
  vulners-mcp:latest
```

### Build & run locally

```bash
git clone https://github.com/vulnersCom/vulners-mcp.git
cd vulners-mcp
poetry install 
export VULNERS_API_KEY="your_api_key"
poetry run python -m vulners_mcp
```

---

## Configuration / Environment Variables

| Variable                       | Type    | Default               | Description                                               |
|--------------------------------|---------|-----------------------|-----------------------------------------------------------|
| `VULNERS_API_KEY`              | string  | *required*            | API key for authenticating with Vulners                   |
| `VULNERS_BASE_URL`             | string  | `https://vulners.com` | Base URL for the Vulners API (without /api suffix)        |
| `MCP_TRANSPORT_MODE`           | string  | `stdio`               | Force transport mode: `http` or `streamable-http`         |
| `FASTMCP_HOST`                 | string  | `0.0.0.0`             | Host/interface on which MCP server binds (HTTP mode only) |
| `FASTMCP_PORT`                 | integer | `8000`                | Port for MCP server (HTTP mode only)                      |
| `FASTMCP_STREAMABLE_HTTP_PATH` | string  | `/mcp`                | Path for the streamable MCP endpoint (HTTP mode only)     |

**Transport Mode:**

- The server automatically detects the transport mode based on how it's run
- Use `MCP_TRANSPORT_MODE=http` to explicitly force HTTP mode (for standalone HTTP server)
- Claude Desktop uses stdio mode automatically when run with `docker run -i`

---

## Usage & Endpoints

### With Claude Desktop

Simply ask questions in natural language:

- "Search for Apache vulnerabilities"
- "Get information about CVE-2024-1234"
- "Audit software cpe:/a:vendor:product:version"

### HTTP Mode

When running in HTTP mode, clients connect to:

```text
http://<FASTMCP_HOST>:<FASTMCP_PORT>/mcp
```

Default: `http://0.0.0.0:8000/mcp`

---

## Testing

Test the HTTP server using the provided test script:

```bash
# Ensure the HTTP server is running
docker ps | grep vulners-mcp

# Run the test script
python3 test_tools.py
```

The test script will:

1. Check server health
2. Initialize MCP protocol
3. List available tools
4. Test CVE search functionality
5. Test Lucene search

---

## Available Tools

The server provides 7 MCP tools for vulnerability research:

### Search & Discovery

- **search_lucene** - 🔍 DISCOVERY TOOL FOR UNKNOWN VULNERABILITIES 🔍 Full-text search in Vulners Knowledge Base using Lucene syntax. Use ONLY when you don't have specific IDs or version information. NEVER use for known CVE/bulletin IDs - use bulletin_by_id instead. NEVER use for specific software versions (e.g., 'Chrome 138.0.7204.184') - use audit_software instead. 🚨 CRITICAL: For vendor/product searches, ALWAYS use cnaAffected.vendor and cnaAffected.product fields - the affectedSoftware field does NOT exist.

- **bulletin_by_id** - 🚨 PRIMARY TOOL FOR KNOWN IDs 🚨 Fetch full bulletin by CVE or Vulners ID. Use this when you have a specific identifier like CVE-2024-1234, RHSA-2024:001, CTX694938, etc. Supports single ID or list of IDs. When list is provided, references are automatically set to False. NEVER use search_lucene for known IDs.

- **query_autocomplete** - Autocomplete helper for search inputs (vendors, products, CVEs, etc.). Get search suggestions from the Vulners database.

- **search_cpe** - Find CPE strings by vendor+product (latest schema). Search for Common Platform Enumeration identifiers in the Vulners database.

### Vulnerability Auditing

- **audit_software** - 🔍 VERSION-SPECIFIC SOFTWARE AUDIT 🔍 Audit specific software versions for known vulnerabilities. Use this when you have exact software version information (e.g., Chrome 138.0.7204.184). NEVER use search_lucene for version-specific software audits.

- **audit_linux_packages** - Linux package audit (RPM/DEB) for a given distro + version. Analyze Linux package vulnerabilities against the Vulners database.

### Information & System Support

- **get_supported_os** - List supported OS identifiers/versions for Linux package audit. Get available operating systems for vulnerability analysis.

### Tool Selection Guidelines

### 🚨 CRITICAL TOOL SELECTION RULES 🚨

#### WHEN TO USE EACH TOOL

- **bulletin_by_id**: Use when you have SPECIFIC IDs
  - ✅ "Analyze CVE-2025-7775" → bulletin_by_id
  - ✅ "Look up CTX694938" → bulletin_by_id  
  - ✅ "Tell me about CVE-2021-44228" → bulletin_by_id
  - ✅ Any specific CVE, RHSA, MS, CTX, NCSC, THN, etc. ID

- **search_lucene**: Use ONLY for DISCOVERY when you don't have specific IDs
  - ✅ "Find vulnerabilities in Apache" → search_lucene
  - ✅ "Show me recent CVEs" → search_lucene
  - ✅ "What vulnerabilities exist in Chrome?" → search_lucene
  - ❌ NEVER use for known IDs - use bulletin_by_id instead

- **audit_software**: Use for VERSION-SPECIFIC software audits
  - ✅ "Audit Chrome 138.0.7204.184" → audit_software
  - ✅ "Check vulnerabilities in Firefox 120.0" → audit_software
  - ✅ Use when you have vendor + product + version information
  - ❌ Don't use for vendor + product only (use search_lucene instead)

**EFFICIENCY RULE**: One bulletin_by_id call is sufficient for known IDs. Do NOT follow up with search_lucene unless explicitly asked to broaden scope.

### Follow-up Workflow for Audit Tools

#### When using audit tools (audit_software, audit_linux_packages)

- ✅ Run the audit tool to identify vulnerable software and get CVE IDs
- ✅ Extract CVE IDs from the response vulnerabilities array
- ✅ Use `bulletin_by_id` with the list of CVE IDs for detailed analysis
- ✅ This provides comprehensive vulnerability information including patches, references, and exploitation data
- ✅ Batch processing with `bulletin_by_id` is more efficient than multiple individual calls

For detailed tool documentation and parameters, use Claude's tool inspection or check the server's tool list.

---

## Development & Contributing

- Open issues or feature requests on GitHub
- Submit pull requests with improvements
- Ensure compatibility with the Vulners API
- Test both stdio (Claude Desktop) and HTTP modes

### Building from Source

```bash
git clone https://github.com/vulnersCom/vulners-mcp.git
cd vulners-mcp
docker build -t vulners-mcp:latest .
```

---

## License

MIT

---

**MCP Name**: `io.github.vulnersCom/vulners-mcp`
