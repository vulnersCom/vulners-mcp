# Vulners MCP Server

**Vulners MCP** is a server implementation that provides the **MCP (Machine‑to‑Machine Content Provider)** interface for the Vulners API. It lets downstream clients (e.g. security scanners, SIEMs, internal tools) query vulnerability data via a streaming / RPC‑style interface while the MCP server handles the communication with Vulners’ REST API behind the scenes.

## Features

- Implements MCP (streamable HTTP or RPC) front for the Vulners API  
- Supports streaming and non‑streaming query modes  
- Configurable via environment variables  
- Deployable via Docker, local build, or pip installation  
- Lightweight and focused on proxying / transforming requests and responses  

## Table of Contents

- [Requirements](#requirements)  
- [Obtaining Vulners API key](#Obtaining-Vulners-API-key)  
- [Installation & Deployment](#installation--deployment)  
  - [Docker (pull from registry)](#docker-pull-from-registry)  
  - [Build & run locally](#build--run-locally)  
  - [Install from PyPI](#install-from-pypi)  
- [Configuration / Environment Variables](#configuration--environment-variables)  
- [Usage & Endpoints](#usage--endpoints)  
- [mcp_server.json](#mcp_serverjson)  
- [Development & Contributing](#development--contributing)  
- [License & Acknowledgements](#license--acknowledgements)

---

## Requirements

- Python 3.9+  
- Access to the Vulners API (valid API key and network connectivity)  
- (For Docker) Docker engine  

---

## Obtaining Vulners API key

Please, register at [Vulners website](https://vulners.com).
Go to the personal menu by clicking at your name at the right top corner.
Follow "API KEYS" tab.
Generate API key with scope "api" and use it with the library.

## Installation & Deployment

### Docker (pull from registry)

You can run the MCP server via a Docker image from the registry:

```bash
docker run \
  -e VULNERS_BASE_URL="https://vulners.com/api" \
  -e VULNERS_API_KEY="your_api_key" \
  -p 8000:8000 \
  vulners/vulners-mcp:latest
```
MCP server will be running at http://0.0.0.0:8000/mcp

### Build & run locally

```bash
git clone https://github.com/vulnersCom/vulners-mcp.git
cd vulners-mcp
poetry install 
poetry run python -m vulners_mcp.server
```

### Install from PyPI

```bash
pip install vulners-mcp
vulners‑mcp --vulners-base-url "$VULNERS_BASE_URL"   --vulners-api-key "$VULNERS_API_KEY"   --host "$FASTMCP_HOST"   --port "$FASTMCP_PORT"   --streamable-path "$FASTMCP_STREAMABLE_HTTP_PATH"
```

---

## Configuration / Environment Variables

| Variable                       | Type    | Default / Required  | Description                                                     |
|--------------------------------|---------|---------------------|-----------------------------------------------------------------|
| `VULNERS_BASE_URL`             | string  | https://vulners.com | Base URL for the Vulners API, override if you want to use proxy |
| `VULNERS_API_KEY`              | string  | *required*          | API key for authenticating with Vulners                         |
| `FASTMCP_HOST`                 | string  | `127.0.0.1`         | Host/interface on which MCP server binds                        |
| `FASTMCP_PORT`                 | integer | `8000`              | Port for MCP server                                             |
| `FASTMCP_STREAMABLE_HTTP_PATH` | string  | `/mcp`              | Path for the streamable MCP endpoint                            |

---

## Usage & Endpoints

Once the MCP server is running, clients should connect to:

```
http://<FASTMCP_HOST>:<FASTMCP_PORT><FASTMCP_STREAMABLE_HTTP_PATH>
```

The endpoint implements MCP semantics—clients may send requests (e.g. query, info, etc.), and receive streaming or chunked responses.

---

## Development & Contributing

- Open issues or feature requests  
- Submit pull requests
- Ensure compatibility with the Vulners API  

---

## License & Acknowledgements

*(Add your preferred license, e.g. MIT, Apache 2.0, etc.)*
