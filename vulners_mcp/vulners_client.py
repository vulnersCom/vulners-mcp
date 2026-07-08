from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Any, Dict

import httpx

from .auth import ANON_TIER_LIMIT_MESSAGE
from .logging_utils import key_fingerprint, log_upstream_call
from .settings import settings

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {"User-Agent": "vulners-mcp/1.0", "Accept": "application/json"}

# Upstream statuses worth retrying: rate limiting and transient gateway/service
# failures. Anything else in the 4xx range is a client-side problem (bad
# request, auth, not found, ...) and retrying it would just repeat the failure.
_RETRIABLE_STATUS_CODES = frozenset({429, 502, 503, 504})

# Total attempts for a single logical call (1 initial + up to 2 retries).
_MAX_ATTEMPTS = 3
_BASE_BACKOFF_SECONDS = 0.5
_MAX_BACKOFF_SECONDS = 8.0

# httpx exceptions that mean "never reached the server" — safe to retry
# because we know for certain no request was processed upstream. Read/write
# timeouts and other transport errors are deliberately excluded: the upstream
# may already have received (and be acting on) the request.
_RETRIABLE_TRANSPORT_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout)


def _sanitize_message(status: int, *, is_anon: bool = False) -> str:
    """Map an upstream HTTP status to a short, safe-to-surface error message.

    Never includes the raw upstream response body — that is only ever logged
    at DEBUG level (see call sites in :class:`VulnersClient`).

    ``is_anon`` distinguishes a 429 that landed on the shared anonymous-tier
    key (``settings.anon_api_key``) from one that landed on a caller's own
    key: the former gets pointed at sending a personal key for full limits,
    the latter gets the generic "slow down" message.
    """
    if status in (401, 403):
        return "API key missing or rejected — see https://mcp.vulners.com/auth.md"
    if status == 429:
        if is_anon:
            return ANON_TIER_LIMIT_MESSAGE
        return "Vulners API rate limit or quota exceeded — slow down and retry later"
    if status >= 500:
        return "Vulners API is temporarily unavailable — please retry later"
    return f"Vulners API rejected the request (HTTP {status})"


def _is_anon_key(key: str | None) -> bool:
    """True if ``key`` is exactly this deployment's configured anon-tier key."""
    return bool(key) and bool(settings.anon_api_key) and key == settings.anon_api_key


class ApiError(RuntimeError):
    """Raised for any failed Vulners API call.

    ``str(error)`` (and ``.message``) is a short, sanitized string that is
    safe to surface to an MCP agent. The raw upstream body, if any, is
    available as ``.upstream_body`` for local debugging but is never included
    in the message itself — callers that want it must log it explicitly at
    DEBUG level.
    """

    def __init__(self, status: int, message: str, *, upstream_body: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.upstream_body = upstream_body


class VulnersClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.vulners_base_url).rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        timeout = httpx.Timeout(
            settings.vulners_connect_timeout_seconds,
            read=settings.vulners_read_timeout_seconds,
        )
        self._client = httpx.AsyncClient(
            base_url=self.base_url, headers=DEFAULT_HEADERS.copy(), timeout=timeout
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _merge(self, per_request: Dict[str, str] | None) -> Dict[str, str]:
        """Build the header set for one request.

        No server-side key is ever injected here: the only source of
        ``X-Api-Key`` (or any other auth header) is whatever the caller
        supplied per-request (forwarded from the inbound MCP request by
        ``server._forward_headers``).
        """
        h = DEFAULT_HEADERS.copy()
        if per_request:
            h.update(per_request)
        return h

    async def _send_with_retry(
        self,
        method: str,
        path: str,
        *,
        json: Dict[str, Any] | None = None,
        params: Dict[str, Any] | None = None,
        headers: Dict[str, str] | None = None,
    ) -> httpx.Response:
        assert self._client, "client not started"
        merged_headers = self._merge(headers)
        request_id = uuid.uuid4().hex
        sent_key = merged_headers.get("X-Api-Key")
        if not sent_key:
            auth_mode = "anonymous"
        elif _is_anon_key(sent_key):
            auth_mode = "anon-tier"
        else:
            auth_mode = "keyed"
        key_fp = key_fingerprint(sent_key)

        last_exc: Exception | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            start = time.monotonic()
            try:
                response = await self._client.request(
                    method, path, json=json, params=params, headers=merged_headers
                )
            except _RETRIABLE_TRANSPORT_ERRORS as exc:
                duration_ms = (time.monotonic() - start) * 1000
                log_upstream_call(
                    request_id=request_id,
                    method=method,
                    path=path,
                    status=None,
                    duration_ms=duration_ms,
                    auth_mode=auth_mode,
                    key_fp=key_fp,
                    result_size=None,
                    attempt=attempt,
                )
                last_exc = exc
                if attempt < _MAX_ATTEMPTS:
                    await self._sleep_before_retry(attempt, retry_after=None)
                    continue
                raise ApiError(
                    0, "Vulners API is temporarily unavailable — please retry later"
                ) from exc
            except httpx.HTTPError as exc:
                # Not retried (e.g. a read/write timeout, where the upstream
                # may already have received and be acting on the request),
                # but still surfaced as a sanitized ApiError rather than a
                # raw httpx exception, so every VulnersClient method has one
                # consistent error type.
                duration_ms = (time.monotonic() - start) * 1000
                log_upstream_call(
                    request_id=request_id,
                    method=method,
                    path=path,
                    status=None,
                    duration_ms=duration_ms,
                    auth_mode=auth_mode,
                    key_fp=key_fp,
                    result_size=None,
                    attempt=attempt,
                )
                logger.debug("Vulners API transport error on %s %s: %s", method, path, exc)
                raise ApiError(
                    0, "Vulners API is temporarily unavailable — please retry later"
                ) from exc

            duration_ms = (time.monotonic() - start) * 1000
            log_upstream_call(
                request_id=request_id,
                method=method,
                path=path,
                status=response.status_code,
                duration_ms=duration_ms,
                auth_mode=auth_mode,
                key_fp=key_fp,
                result_size=len(response.content),
                attempt=attempt,
            )

            if response.status_code in _RETRIABLE_STATUS_CODES and attempt < _MAX_ATTEMPTS:
                await self._sleep_before_retry(
                    attempt, retry_after=response.headers.get("Retry-After")
                )
                continue

            return response

        # Unreachable: the loop above always either returns or raises on the
        # final attempt. Kept only to satisfy static type checkers.
        raise ApiError(
            0, "Vulners API is temporarily unavailable — please retry later"
        ) from last_exc

    async def _sleep_before_retry(self, attempt: int, retry_after: str | None) -> None:
        await asyncio.sleep(self._compute_backoff(attempt, retry_after))

    @staticmethod
    def _compute_backoff(attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass  # non-numeric Retry-After (HTTP-date); fall back to backoff
        base = min(_MAX_BACKOFF_SECONDS, _BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        return base + random.uniform(0, base * 0.25)  # jitter

    def _error_for_status(self, response: httpx.Response) -> ApiError:
        logger.debug(
            "Vulners API error status=%s url=%s body=%s",
            response.status_code,
            response.request.url,
            response.text,
        )
        sent_key = response.request.headers.get("x-api-key")
        return ApiError(
            response.status_code,
            _sanitize_message(response.status_code, is_anon=_is_anon_key(sent_key)),
            upstream_body=response.text,
        )

    def _unwrap(self, response: httpx.Response) -> Any:
        """Validate the HTTP status, then unwrap the ``{"result", "data"}`` envelope.

        Vulners responses are shaped ``{"result": "OK", "data": {...}}``. On
        success this returns ``data``; a non-OK ``result`` or an HTTP error
        status both raise :class:`ApiError`.
        """
        if response.status_code >= 400:
            raise self._error_for_status(response)

        try:
            body = response.json()
        except ValueError as exc:
            logger.debug(
                "Non-JSON 2xx response from %s: %s", response.request.url, response.text
            )
            raise ApiError(
                response.status_code, "Vulners API returned an unreadable response"
            ) from exc

        if isinstance(body, dict) and "result" in body:
            if body.get("result") == "OK":
                return body.get("data")
            logger.debug(
                "Vulners API result!=OK for %s: %s", response.request.url, body
            )
            raise ApiError(
                response.status_code,
                _sanitize_message(response.status_code),
                upstream_body=str(body),
            )

        # A handful of endpoints don't use the envelope; pass the body through.
        return body

    async def _post(
        self, path: str, json: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        response = await self._send_with_retry("POST", path, json=json, headers=headers)
        return self._unwrap(response)

    async def _get(
        self,
        path: str,
        params: Dict[str, Any] | None = None,
        headers: Dict[str, str] | None = None,
    ) -> Any:
        response = await self._send_with_retry("GET", path, params=params, headers=headers)
        ct = response.headers.get("content-type", "")
        if not ct.startswith("application/json"):
            if response.status_code >= 400:
                raise self._error_for_status(response)
            return response.content
        return self._unwrap(response)

    # ---- wrappers (all accept headers) ----
    async def search_lucene(
        self, body: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        return await self._post("/api/v3/search/lucene", body, headers=headers)

    async def search_by_id(
        self, body: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        return await self._post("/api/v3/search/id", body, headers=headers)

    async def audit_software(
        self, body: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        return await self._post("/api/v4/audit/software", body, headers=headers)

    async def audit_linux_packages(
        self, body: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        return await self._post("/api/v4/audit/linux", body, headers=headers)

    async def get_supported_os(self, headers: Dict[str, str] | None = None) -> Any:
        return await self._get("/api/v3/audit/getSupportedOS", headers=headers)

    async def query_autocomplete(
        self, body: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> Any:
        return await self._post("/api/v3/search/autocomplete", body, headers=headers)

    async def search_cpe(
        self,
        vendor: str,
        product: str,
        size: int | None = None,
        headers: Dict[str, str] | None = None,
    ) -> Any:
        params: Dict[str, Any] = {"vendor": vendor, "product": product}
        if size is not None:
            params["size"] = size
        return await self._get("/api/v4/search/cpe", params=params, headers=headers)
