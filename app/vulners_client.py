from __future__ import annotations
import httpx
from typing import Any, Dict, Optional
from .settings import settings

DEFAULT_HEADERS = {"User-Agent": "vulners-mcp/1.0", "Accept": "application/json"}

class ApiError(RuntimeError):
    def __init__(self, status: int, payload: Any):
        super().__init__(f"Vulners API error {status}: {payload}")
        self.status = status
        self.payload = payload

class VulnersClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.base_url = (base_url or settings.vulners_base_url).rstrip("/")
        self.api_key = api_key or settings.vulners_api_key
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(base_url=self.base_url,
                                         headers=DEFAULT_HEADERS.copy(),
                                         timeout=30)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _merge(self, per_request: Dict[str, str] | None) -> Dict[str, str]:
        h = DEFAULT_HEADERS.copy()
        if per_request:
            h.update(per_request)  # include X-Api-Key / Authorization from caller
        if "X-Api-Key" not in {k.title() for k in h.keys()} and self.api_key:
            h["X-Api-Key"] = self.api_key
        return h

    async def _post(self, path: str, json: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        assert self._client, "client not started"
        r = await self._client.post(path, json=json, headers=self._merge(headers))
        if r.status_code >= 400:
            raise ApiError(r.status_code, r.text)
        return r.json()

    async def _get(self, path: str, params: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None) -> Any:
        assert self._client, "client not started"
        r = await self._client.get(path, params=params, headers=self._merge(headers))
        if r.status_code >= 400:
            raise ApiError(r.status_code, r.text)
        ct = r.headers.get("content-type", "")
        return r.json() if ct.startswith("application/json") else r.content

    # ---- wrappers (all accept headers) ----
    async def search_lucene(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/search/lucene", body, headers=headers)

    async def search_by_id(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/search/id", body, headers=headers)

    async def audit_software(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v4/audit/software", body, headers=headers)

    async def audit_host(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v4/audit/host", body, headers=headers)

    async def audit_windows_kb(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/audit/kb", body, headers=headers)

    async def audit_windows(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/audit/winaudit", body, headers=headers)

    async def audit_linux_packages(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/audit/audit", body, headers=headers)

    async def get_supported_os(self, headers: Dict[str, str] | None = None) -> Any:
        return await self._get("/api/v3/audit/getSupportedOS", headers=headers)

    async def query_autocomplete(self, body: Dict[str, Any], headers: Dict[str, str] | None = None) -> Any:
        return await self._post("/api/v3/search/autocomplete", body, headers=headers)

    async def search_cpe(self, vendor: str, product: str, size: int | None = None, headers: Dict[str, str] | None = None) -> Any:
        params: Dict[str, Any] = {"vendor": vendor, "product": product}
        if size is not None:
            params["size"] = size
        return await self._get("/api/v4/search/cpe", params=params, headers=headers)

    async def fetch_collection(self, type_: str, headers: Dict[str, str] | None = None) -> Any:
        return await self._get("/api/v4/archive/collection", params={"type": type_}, headers=headers)

    async def fetch_collection_update(self, type_: str, after_iso: str, headers: Dict[str, str] | None = None) -> Any:
        return await self._get("/api/v4/archive/collection-update", params={"type": type_, "after": after_iso}, headers=headers)

    async def get_os_cve_archive(self, os: str, version: str, headers: Dict[str, str] | None = None) -> bytes:
        data = await self._get("/api/v3/archive/distributive", params={"os": os, "version": version}, headers=headers)
        assert isinstance(data, (bytes, bytearray))
        return data
