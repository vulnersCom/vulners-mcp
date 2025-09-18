from __future__ import annotations
import os
from pydantic import BaseModel, Field

class Settings(BaseModel):
    # Vulners
    vulners_base_url: str = Field(default="https://vulners.com")
    vulners_api_key: str = Field(default_factory=lambda: os.getenv("VULNERS_API_KEY", ""))

    # FastMCP server config
    host: str = Field(default=os.getenv("MCP_HOST", "0.0.0.0"))
    port: int = Field(default=int(os.getenv("MCP_PORT", "8000")))
    # Default Streamable HTTP path is /mcp/ in FastMCP; keep it explicit:
    streamable_http_path: str = Field(default=os.getenv("MCP_HTTP_PATH", "/mcp/"))

settings = Settings()
