from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Vulners
    vulners_base_url: str = "https://vulners.com"
    vulners_api_key: str = ""


settings = Settings()
