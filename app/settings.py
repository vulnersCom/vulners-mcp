from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Vulners
    vulners_base_url: str = "https://vulners.com"
    vulners_api_key: str = ""
    
    # MCP Server
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_http_path: str = "/mcp/"


settings = Settings()
